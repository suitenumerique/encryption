import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parseAllDocuments, parse as parseYaml } from 'yaml';

/**
 * The stack chart is four subcharts and a bootstrap Job, so what can go wrong is not one
 * chart's shape but the seams between them: a product told to reach a database the
 * bootstrap never creates, a client the realm does not have, a vault origin the product
 * is not allowed to embed. templates/_checks.tpl turns each of those into a render
 * error; this file proves every check fires, and that the objects the chart owns are
 * what the snapshot says.
 *
 * Needs `helm` on the PATH and the network (the product charts come from GitHub Pages).
 */

const CHART = resolve(import.meta.dirname, 'suite-stack');
const STAGING_VALUES = resolve(CHART, 'ci/staging-values.yaml');
const ROLE_SCRIPTS = resolve(import.meta.dirname, '../postgres');
const PREVIEW_HELMFILE = resolve(import.meta.dirname, '../helmfile/preview/helmfile.yaml.gotmpl');

interface EnvEntry {
  name: string;
  value?: string;
  valueFrom?: { secretKeyRef?: { name: string; key: string } };
}

interface Container {
  name: string;
  image: string;
  env?: EnvEntry[];
  command?: string[];
}

interface Manifest {
  kind: string;
  metadata: { name: string; annotations?: Record<string, string>; labels?: Record<string, string> };
  stringData?: Record<string, string>;
  data?: Record<string, string>;
  spec?: { template?: { spec: { initContainers?: Container[]; containers: Container[] } } };
}

function run(command: string, args: string[], input?: string, env?: NodeJS.ProcessEnv): string {
  try {
    return execFileSync(command, args, { encoding: 'utf8', input, stdio: ['pipe', 'pipe', 'pipe'], env: { ...process.env, ...env } });
  } catch (error) {
    const failure = error as { stderr?: string; stdout?: string; message: string };

    throw new Error(`${command} ${args.join(' ')} failed:\n${failure.stderr || failure.stdout || failure.message}`, { cause: error });
  }
}

function isInstalled(command: string, versionArgs: string[]): boolean {
  try {
    execFileSync(command, versionArgs, { stdio: 'ignore' });

    return true;
  } catch {
    return false;
  }
}

// The subcharts, fetched every run with `dependency update`, not `build`: with a
// Chart.lock, `build` wants every repository registered with `helm repo add`, `update`
// resolves the URLs itself. The local encryption chart is packaged again each time, since
// an existing archive is kept whatever the checkout now contains.
function buildDependencies(): void {
  const charts = resolve(CHART, 'charts');

  if (existsSync(charts)) {
    for (const archive of readdirSync(charts).filter((name) => name.startsWith('encryption-chart-'))) {
      rmSync(resolve(charts, archive));
    }
  }

  run('helm', ['dependency', 'update', CHART]);
}

interface Render {
  text: string;
  docs: Manifest[];
  /** The objects this chart renders itself, apart from the subcharts'. */
  own: Manifest[];
  /** Same, plus the encryption service's: the two charts this repository answers for. */
  ours: string;
}

function render(values: string[] = [], set: string[] = [], setJson: string[] = []): Render {
  const text = run('helm', [
    'template',
    'stack',
    CHART,
    '--namespace',
    'suite',
    ...values.flatMap((file) => ['--values', file]),
    ...set.flatMap((entry) => ['--set', entry]),
    ...setJson.flatMap((entry) => ['--set-json', entry]),
  ]);
  const chunks = text.split(/^---$/m).filter((chunk) => chunk.trim() !== '');
  const isOurs = (chunk: string) => /^# Source: suite-stack\/(?:templates|charts\/encryption)\//m.test(chunk);
  const parse = (chunk: string) =>
    parseAllDocuments(chunk)
      .map((document) => document.toJS() as Manifest | null)
      // A product chart renders an empty CronJobList, an object without metadata.
      .filter((document): document is Manifest => document !== null && typeof document === 'object' && 'metadata' in document);

  return {
    text,
    docs: chunks.flatMap(parse),
    own: chunks.filter((chunk) => /^# Source: suite-stack\/templates\//m.test(chunk)).flatMap(parse),
    ours: chunks.filter(isOurs).join('\n---\n'),
  };
}

function renderError(set: string[], setJson: string[] = []): string {
  try {
    render([], set, setJson);
  } catch (error) {
    return (error as Error).message;
  }

  throw new Error('expected the render to fail');
}

function find(docs: Manifest[], kind: string, name: string): Manifest {
  const found = docs.find((document) => document.kind === kind && document.metadata.name === name);

  if (!found) throw new Error(`no ${kind} named ${name} in the render`);

  return found;
}

function containerEnv(container: Container | undefined): Map<string, EnvEntry> {
  return new Map((container?.env ?? []).map((entry) => [entry.name, entry]));
}

function mainContainer(manifest: Manifest, name?: string): Container {
  const containers = manifest.spec?.template?.spec.containers ?? [];
  const container = name ? containers.find((candidate) => candidate.name === name) : containers[0];

  if (!container) throw new Error(`no container ${name ?? ''} in ${manifest.kind} ${manifest.metadata.name}`);

  return container;
}

const defaults = parseYaml(readFileSync(resolve(CHART, 'values.yaml'), 'utf8')) as {
  bootstrap: { keycloak: { clients: { clientId: string; public?: boolean; secret?: string; redirectUris: string[]; webOrigins: string[] }[] } };
};

if (!isInstalled('helm', ['version', '--short'])) {
  throw new Error('The chart tests need the helm binary on the PATH (brew install helm, or https://helm.sh/docs/intro/install/)');
}

buildDependencies();

describe('the stack chart', () => {
  const full = render();
  const staging = render([STAGING_VALUES]);
  // A developer's own override, validated on demand: SUITE_STACK_VALUES=my-values.yaml npm run test:helm
  const custom = process.env.SUITE_STACK_VALUES ? render([process.env.SUITE_STACK_VALUES]) : undefined;

  it('lints strictly and validates our objects against the Kubernetes API schemas', () => {
    expect(run('helm', ['lint', '--strict', CHART])).toContain('0 chart(s) failed');

    if (!isInstalled('kubeconform', ['-v'])) {
      if (process.env.CI) throw new Error('kubeconform is required in CI');
      console.warn('kubeconform is not installed, skipping the API schema validation (brew install kubeconform)');

      return;
    }

    const cache = mkdtempSync(resolve(tmpdir(), 'kubeconform-'));

    // Only what this repository renders: the product charts are validated upstream, and
    // one object of the shared chart (its MinIO StatefulSet, missing `serviceName`) does
    // not pass the 1.30 schemas.
    for (const { ours } of [full, staging, ...(custom ? [custom] : [])]) {
      const summary = run('kubeconform', ['-strict', '-summary', '-kubernetes-version', '1.30.0', '-cache', cache], ours);

      expect(summary).toMatch(/Invalid: 0/);
      expect(summary).toMatch(/Errors: 0/);
    }
  });

  it('renders the same objects of its own as last time (review the snapshot diff on any change)', () => {
    expect(full.own.map((document) => `${document.kind}/${document.metadata.name}`).sort()).toEqual(
      [
        'Secret/stack-suite-stack-bootstrap-1',
        'Job/stack-suite-stack-bootstrap-1',
        'Deployment/mailpit',
        'Service/mailpit',
        'Ingress/mailpit',
        'ConfigMap/onlyoffice',
        'Deployment/onlyoffice',
        'Service/onlyoffice',
        'Ingress/onlyoffice',
      ].sort()
    );
    expect(
      full.text
        .split(/^---$/m)
        .filter((chunk) => /^# Source: suite-stack\/templates\//m.test(chunk))
        .join('\n---\n')
    ).toMatchSnapshot();
  });

  it('ships the role scripts of deploy/postgres, unchanged', () => {
    for (const script of ['create-migrator-role.sql', 'create-runtime-role.sql']) {
      expect(readFileSync(resolve(CHART, 'files/postgres', script), 'utf8')).toBe(readFileSync(resolve(ROLE_SCRIPTS, script), 'utf8'));
    }
  });

  it('gives every product the same shared services, by fixed names', () => {
    for (const name of ['postgres', 'redis', 'minio', 'shared-keycloak', 'mailpit', 'onlyoffice']) {
      find(full.docs, 'Service', name);
    }

    const keycloak = containerEnv(
      find(full.own, 'Job', 'stack-suite-stack-bootstrap-1').spec?.template?.spec.initContainers?.find((c) => c.name === 'keycloak')
    );

    expect(keycloak.get('KEYCLOAK_HOST')?.value).toBe('shared-keycloak');

    const docs = containerEnv(mainContainer(find(full.docs, 'Deployment', 'docs-backend')));
    const drive = containerEnv(mainContainer(find(full.docs, 'Deployment', 'drive-backend')));
    const encryption = containerEnv(mainContainer(find(full.docs, 'Deployment', 'stack-encryption')));

    for (const env of [docs, drive]) {
      expect(env.get('DB_HOST')?.value).toBe('postgres');
      expect(env.get('REDIS_URL')?.value).toMatch(/^redis:\/\/[^@]+@redis:6379\//);
      expect(env.get('DJANGO_EMAIL_HOST')?.value).toBe('mailpit');
      expect(env.get('OIDC_OP_JWKS_ENDPOINT')?.value).toBe('https://auth.suite.example.org/realms/suite/protocol/openid-connect/certs');
    }

    expect(docs.get('AWS_S3_ENDPOINT_URL')?.value).toBe('http://minio:9000');
    expect(drive.get('WOPI_ONLYOFFICE_DISCOVERY_URL')?.value).toBe('http://onlyoffice/hosting/discovery');
    expect(drive.get('WOPI_SRC_BASE_URL')?.value).toBe('https://drive.suite.example.org');
    expect(containerEnv(mainContainer(find(full.own, 'Deployment', 'onlyoffice'))).get('JWT_SECRET')?.value).toBe(
      drive.get('WOPI_ONLYOFFICE_CONVERT_JWT_SECRET')?.value
    );
    expect(find(full.own, 'ConfigMap', 'onlyoffice').data?.['local-production-linux.json']).toBe(
      '{"wopi":{"host":"https://office.suite.example.org"}}'
    );
    // Drive's own Job, told to wait for the server, like the migration waits for the database.
    expect(mainContainer(find(full.docs, 'Job', 'drive-backend-configure-wopi')).command?.join(' ')).toContain('until python -c');
    expect(docs.get('REDIS_URL')?.value).not.toBe(drive.get('REDIS_URL')?.value);
    expect(encryption.get('MAILER_SMTP_HOST')?.value).toBe('mailpit');
    expect(encryption.get('OIDC_ISSUER')?.value).toBe('https://auth.suite.example.org/realms/suite');

    const secret = find(full.docs, 'Secret', encryption.get('DATABASE_URL')?.valueFrom?.secretKeyRef?.name ?? '');

    expect(secret.stringData?.DATABASE_URL).toBe('postgresql://encryption_runtime:runtime@postgres:5432/encryption?schema=encryption');
  });

  it('bootstraps after the shared services exist and before an upgrade rolls out', () => {
    const job = find(full.own, 'Job', 'stack-suite-stack-bootstrap-1');
    const secret = find(full.own, 'Secret', 'stack-suite-stack-bootstrap-1');

    expect(job.metadata.annotations?.['helm.sh/hook']).toBe('post-install,pre-upgrade');
    expect(secret.metadata.annotations?.['helm.sh/hook']).toBe('post-install,pre-upgrade');
    expect(Number(secret.metadata.annotations?.['helm.sh/hook-weight'])).toBeLessThan(Number(job.metadata.annotations?.['helm.sh/hook-weight']));

    // Sequential: init containers, in the order the products need them.
    expect(job.spec?.template?.spec.initContainers?.map((container) => container.name)).toEqual(['postgres', 'minio', 'keycloak']);

    const scripts = secret.stringData ?? {};

    for (const database of ['docs', 'drive', 'encryption']) {
      expect(scripts['postgres.sh']).toContain(`CREATE DATABASE "${database}"`);
    }

    expect(scripts['postgres.sh']).toContain('create-migrator-role.sql');
    expect(scripts['minio.sh']).toContain('mc mb --ignore-existing "local/drive-media-storage"');

    for (const client of ['docs', 'drive', 'encryption']) {
      expect(scripts['keycloak.sh']).toContain(`ensure_client '${client}' `);
    }

    expect(scripts['keycloak.sh']).toContain(`ensure_user 'alice.martin' `);

    // The notice every tester reads: on the sign-in pages, and as terms accepted once.
    const keycloak = containerEnv(job.spec?.template?.spec.initContainers?.find((container) => container.name === 'keycloak'));

    expect(keycloak.get('NOTICE_HEADER')?.value).toBe("Environnement de test : rien n'y est privé");
    expect(keycloak.get('NOTICE_HEADER_HTML')?.value).toBe('Environnement de test : rien n&#39;y est privé');
    expect(scripts['keycloak.sh']).toContain('-s "displayNameHtml=${NOTICE_HEADER_HTML}" -s internationalizationEnabled=true');
    expect(JSON.parse(scripts['notice.json']).termsText).toContain("N'y mettez aucune donnée réelle");
    expect(scripts['keycloak.sh']).toContain(`localization/fr" -f /scripts/notice.json`);
    expect(scripts['keycloak.sh']).toContain(`grep -i '^terms_and_conditions$'`);
    expect(scripts['keycloak.sh']).toContain('required-actions/${TERMS}" -r "$REALM" -s enabled=true -s defaultAction=true');
    expect(scripts['keycloak.sh']).toContain('-s "requiredActions=[\\"${TERMS}\\"]"');
  });

  // Argo CD ignores the Helm hook annotations of an object that carries its own, and would
  // otherwise run the bootstrap in PreSync (from `pre-upgrade`), before the shared
  // services exist. It is a Sync hook instead. No sync waves anywhere: a wave waits for
  // every object before it to be healthy, and the shared chart's bucket Job is deleted by
  // Kubernetes the moment it completes, so Argo CD reports it Missing and a wave after it
  // never starts. Every consumer waits for what it needs by itself.
  it('runs its bootstrap as an Argo CD Sync hook, with no sync wave to get stuck on', () => {
    const annotation = (document: Manifest, name: string) => document.metadata.annotations?.[`argocd.argoproj.io/${name}`];

    for (const kind of ['Secret', 'Job']) {
      expect(annotation(find(full.own, kind, 'stack-suite-stack-bootstrap-1'), 'hook'), kind).toBe('Sync');
    }

    expect(annotation(find(full.own, 'Job', 'stack-suite-stack-bootstrap-1'), 'hook-delete-policy')).toContain('HookSucceeded');

    for (const name of ['docs-backend-migrate', 'drive-backend-migrate', 'docs-backend-createsuperuser', 'drive-backend-createsuperuser']) {
      expect(annotation(find(full.docs, 'Job', name), 'hook'), name).toBe('Sync');
    }

    for (const document of full.docs) {
      expect(annotation(document, 'sync-wave'), `${document.kind}/${document.metadata.name}`).toBeUndefined();
    }
  });

  it('migrates the encryption service itself, with the migrator role and the deployed image', () => {
    const job = find(full.own, 'Job', 'stack-suite-stack-bootstrap-1');
    const migrate = mainContainer(job, 'migrate');
    const server = mainContainer(find(full.docs, 'Deployment', 'stack-encryption'));

    expect(migrate.image).toBe(server.image);
    expect(containerEnv(migrate).get('DATABASE_URL')?.valueFrom?.secretKeyRef).toEqual({
      name: 'stack-suite-stack-bootstrap-1',
      key: 'ENCRYPTION_MIGRATION_DATABASE_URL',
    });
    expect(find(full.own, 'Secret', 'stack-suite-stack-bootstrap-1').stringData?.ENCRYPTION_MIGRATION_DATABASE_URL).toBe(
      'postgresql://encryption_migrator:migrator@postgres:5432/encryption?schema=encryption'
    );
    // Not twice: the service's own hook is off, so nothing of its migration is rendered.
    expect(full.docs.filter((document) => document.metadata.labels?.['app.kubernetes.io/component'] === 'migration')).toEqual([]);
  });

  it('takes the images of the branches under test from the override file', () => {
    expect(mainContainer(find(staging.docs, 'Deployment', 'docs-backend')).image).toBe('myaccount/impress-backend:e2ee');
    expect(mainContainer(find(staging.docs, 'Deployment', 'docs-frontend')).image).toBe('myaccount/impress-frontend:e2ee');
    expect(mainContainer(find(staging.docs, 'Deployment', 'docs-y-provider')).image).toBe('myaccount/impress-y-provider:e2ee');
    expect(mainContainer(find(staging.docs, 'Deployment', 'drive-backend')).image).toBe('myaccount/drive-backend:e2ee');
    expect(mainContainer(find(staging.docs, 'Deployment', 'drive-frontend')).image).toBe('myaccount/drive-frontend:e2ee');
    expect(mainContainer(find(staging.docs, 'Deployment', 'stack-encryption')).image).toBe('myaccount/encryption:e2ee');
    expect(mainContainer(find(staging.own, 'Job', 'stack-suite-stack-bootstrap-1'), 'migrate').image).toBe('myaccount/encryption:e2ee');
  });

  it('refuses a stack whose blocks disagree, naming both values', () => {
    const cases: [string, RegExp][] = [
      ['docs.backend.envVars.DB_NAME=other', /DB_NAME "other" must be listed in bootstrap\.postgres\.databases/],
      ['drive.backend.envVars.DB_HOST=db', /drive\.backend\.envVars\.DB_HOST must be the shared PostgreSQL, "postgres"/],
      ['docs.backend.envVars.AWS_STORAGE_BUCKET_NAME=other', /AWS_STORAGE_BUCKET_NAME "other" must be shared\.minio\.bucket or listed/],
      ['docs.backend.envVars.OIDC_RP_CLIENT_ID=other', /OIDC_RP_CLIENT_ID "other" has no entry in bootstrap\.keycloak\.clients/],
      ['drive.backend.envVars.OIDC_RP_CLIENT_SECRET=other', /OIDC_RP_CLIENT_SECRET differs from bootstrap\.keycloak\.clients\[drive\]\.secret/],
      ['docs.backend.envVars.OIDC_OP_JWKS_ENDPOINT=https://other/certs', /OIDC_OP_JWKS_ENDPOINT must be under the shared Keycloak's realm/],
      ['drive.backend.envVars.REDIS_URL=redis://user:pass@redis:6379/1', /docs and drive share the Redis URL/],
      ['docs.backend.envVars.ENCRYPTION_FEATURE_ENABLED=False', /ENCRYPTION_FEATURE_ENABLED must be "True"/],
      ['drive.backend.envVars.ENCRYPTION_VAULT_URL=https://other', /ENCRYPTION_VAULT_URL must be "https:\/\/data\.encryption\.suite\.example\.org"/],
      ['docs.backend.envVars.ENCRYPTION_INTERFACE_URL=https://other', /ENCRYPTION_INTERFACE_URL must be "https:\/\/encryption\.suite\.example\.org"/],
      [
        'encryption.config.allowedFrameAncestors={https://docs.suite.example.org}',
        /allowedFrameAncestors must contain "https:\/\/drive\.suite\.example\.org"/,
      ],
      ['drive.backend.envVars.WOPI_CLIENTS=collabora', /WOPI_CLIENTS must be "onlyoffice"/],
      [
        'drive.backend.envVars.WOPI_ONLYOFFICE_DISCOVERY_URL=http://other/hosting/discovery',
        /WOPI_ONLYOFFICE_DISCOVERY_URL must be "http:\/\/onlyoffice\/hosting\/discovery"/,
      ],
      ['drive.backend.envVars.WOPI_SRC_BASE_URL=https://other', /WOPI_SRC_BASE_URL must be "https:\/\/drive\.suite\.example\.org"/],
      ['drive.backend.envVars.WOPI_ONLYOFFICE_CONVERT_JWT_SECRET=other', /WOPI_ONLYOFFICE_CONVERT_JWT_SECRET differs from onlyoffice\.jwtSecret/],
      ['encryption.database.url=postgresql://other', /encryption\.database\.url must be the runtime role's URL/],
      ['encryption.config.oidc.issuer=https://other/realms/suite', /issuer must be the shared Keycloak's realm/],
      ['encryption.config.oidc.jwksUrl=https://other/certs', /jwksUrl must be/],
      ['encryption.config.oidc.clientId=other', /clientId "other" has no entry in bootstrap\.keycloak\.clients/],
      ['encryption.config.mailer.smtpHost=smtp.example.org', /smtpHost must be "mailpit"/],
      ['bootstrap.encryption.database=other', /bootstrap\.encryption\.database "other" must be listed/],
      ['shared.postgres.serviceNameOverride=', /shared\.postgres\.serviceNameOverride is required/],
      ['shared.fullnameOverride=', /shared\.fullnameOverride is required/],
      ['shared.redis.enabled=false', /shared\.redis\.enabled must be true/],
    ];

    for (const [set, message] of cases) {
      expect(renderError([set]), set).toMatch(message);
    }
  });

  it('refuses a client of the wrong kind, or one missing the redirect URI a product needs', () => {
    // `--set` on a list index drops the other entries, so the whole list goes as JSON.
    const clients = (edit: (client: (typeof defaults.bootstrap.keycloak.clients)[number]) => void) =>
      `bootstrap.keycloak.clients=${JSON.stringify(
        defaults.bootstrap.keycloak.clients.map((client) => {
          const copy = structuredClone(client);

          edit(copy);

          return copy;
        })
      )}`;

    expect(
      renderError(
        [],
        [
          clients((client) => {
            if (client.clientId === 'encryption') {
              client.public = false;
              client.secret = 'x';
            }
          }),
        ]
      )
    ).toMatch(/clients\[encryption\] must be public/);
    expect(
      renderError(
        [],
        [
          clients((client) => {
            if (client.clientId === 'docs') client.public = true;
          }),
        ]
      )
    ).toMatch(/clients\[docs\] must be confidential/);
    expect(
      renderError(
        [],
        [
          clients((client) => {
            if (client.clientId === 'drive') client.redirectUris = ['https://other/*'];
          }),
        ]
      )
    ).toMatch(/clients\[drive\]\.redirectUris must contain "https:\/\/drive\.suite\.example\.org\/\*"/);
    expect(
      renderError(
        [],
        [
          clients((client) => {
            if (client.clientId === 'encryption') client.redirectUris = ['https://other/auth/callback'];
          }),
        ]
      )
    ).toMatch(/clients\[encryption\]\.redirectUris must contain "https:\/\/encryption\.suite\.example\.org\/auth\/callback"/);
  });

  // The per-pull-request environment: every hostname derived from `feature` and `domain`
  // by deploy/helmfile/preview, on top of the chart's values, through helmfile itself.
  it('derives a whole preview environment from a pull request number and a domain', () => {
    if (!isInstalled('helmfile', ['--version'])) {
      if (process.env.CI) throw new Error('helmfile is required in CI');
      console.warn('helmfile is not installed, skipping the preview environment render (brew install helmfile)');

      return;
    }

    const text = run('helmfile', [
      '-e',
      'preview',
      '-f',
      PREVIEW_HELMFILE,
      '--state-values-set',
      'feature=42,domain=ppr.example.net',
      '--state-values-set',
      'images.docs.tag=pr-42,images.docsFrontend.tag=pr-42,images.docsYProvider.tag=pr-42,images.drive.tag=pr-42,images.driveFrontend.tag=pr-42,images.encryption.tag=pr-42',
      'template',
    ]);

    // Nothing of the placeholder domain or namespace survives: a hostname the helmfile
    // forgot to derive would silently point a product at the wrong environment.
    expect(text).not.toMatch(/suite\.example\.org|suite\.svc/);

    for (const host of [
      '42-docs.ppr.example.net',
      '42-drive.ppr.example.net',
      '42-encryption.ppr.example.net',
      'data.42-encryption.ppr.example.net',
      '42-auth.ppr.example.net',
      '42-s3.ppr.example.net',
      '42-s3-console.ppr.example.net',
      '42-mail.ppr.example.net',
      '42-office.ppr.example.net',
    ]) {
      expect(text, host).toContain(host);
    }

    expect(text).toContain('namespace: "preview-42"');
    expect(text).toContain('minio.preview-42.svc.cluster.local');
    expect(text).toContain('image: "lasuite/impress-backend:pr-42"');
    expect(text).toContain('image: "lasuite/drive-backend:pr-42"');
    expect(text).toContain('image: "lasuite/encryption:pr-42"');
    expect(text).not.toMatch(/image: "lasuite\/(?:impress|drive)-[a-z-]+:main"/);
  });

  // Argo CD hands the inputs to its plugin as environment variables of the Application,
  // which a sidecar plugin sees prefixed. Without this path every preview renders the
  // defaults, `ci-docs.example.org`, and the ingress answers nothing.
  it('reads the preview inputs from the environment, a state value winning over it', () => {
    if (!isInstalled('helmfile', ['--version'])) return;

    const args = ['-e', 'preview', '-f', PREVIEW_HELMFILE, 'template'];
    const fromEnvironment = run('helmfile', args, undefined, { FEATURE: '7', DOMAIN: 'ppr.example.net' });

    expect(fromEnvironment).toContain('7-docs.ppr.example.net');
    expect(fromEnvironment).toContain('namespace: "preview-7"');
    expect(fromEnvironment).not.toMatch(/ci-[a-z]+\.example\.org/);

    // A number is a pull request: its own image, the tag the preview workflow publishes
    expect(fromEnvironment).toContain('image: "lasuite/encryption:pr-7"');
    expect(run('helmfile', args, undefined, { FEATURE: 'beta', DOMAIN: 'ppr.example.net' })).toContain('image: "lasuite/encryption:main"');

    const prefixed = run('helmfile', args, undefined, {
      ARGOCD_ENV_FEATURE: '8',
      ARGOCD_ENV_DOMAIN: 'ppr.example.net',
      ARGOCD_ENV_ENCRYPTION_IMAGE: 'lasuite/encryption:sha-0123abcd',
    });

    expect(prefixed).toContain('8-encryption.ppr.example.net');
    expect(prefixed).toContain('image: "lasuite/encryption:sha-0123abcd"');
    expect(() => run('helmfile', args, undefined, { ENCRYPTION_IMAGE: 'no-tag' })).toThrow(/ENCRYPTION_IMAGE must be repository:tag/);

    const overridden = run('helmfile', [...args.slice(0, -1), '--state-values-set', 'feature=9', 'template'], undefined, {
      FEATURE: '7',
      DOMAIN: 'ppr.example.net',
    });

    expect(overridden).toContain('9-docs.ppr.example.net');
    expect(overridden).not.toContain('7-docs.');
  });

  it('rejects a password or a name the scripts could not quote', () => {
    expect(renderError(["bootstrap.keycloak.users[0].password=a'b"])).toMatch(/does not match pattern/);
    expect(renderError(['bootstrap.encryption.runtimePassword=a b'])).toMatch(/does not match pattern/);
    expect(renderError(['bootstrap.postgres.databases[0]=Docs'])).toMatch(/does not match pattern/);
  });

  it('renders nothing for a product that is off, and no migration without the service', () => {
    const without = render(
      [],
      ['encryption.enabled=false', 'docs.backend.envVars.ENCRYPTION_FEATURE_ENABLED=False', 'drive.backend.envVars.ENCRYPTION_FEATURE_ENABLED=False']
    );

    expect(without.docs.some((document) => document.metadata.name.startsWith('stack-encryption'))).toBe(false);
    expect(mainContainer(find(without.own, 'Job', 'stack-suite-stack-bootstrap-1')).name).toBe('done');
    expect(find(without.own, 'Secret', 'stack-suite-stack-bootstrap-1').stringData?.['postgres.sh']).not.toContain('create-migrator-role');

    const shared = render(
      [],
      [
        'docs.enabled=false',
        'drive.enabled=false',
        'mailpit.enabled=false',
        'onlyoffice.enabled=false',
        'encryption.config.mailer.smtpHost=smtp.example.org',
      ]
    );
    const names = shared.docs.map((document) => document.metadata.name);

    expect(names.some((name) => name.startsWith('docs-') || name.startsWith('drive-') || name === 'mailpit' || name === 'onlyoffice')).toBe(false);
    find(shared.docs, 'Deployment', 'stack-encryption');
  });
});
