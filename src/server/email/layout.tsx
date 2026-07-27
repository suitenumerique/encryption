import {
  Mjml,
  MjmlAll,
  MjmlAttributes,
  MjmlBody,
  MjmlButton,
  MjmlColumn,
  MjmlDivider,
  MjmlGroup,
  MjmlHead,
  MjmlImage,
  MjmlRaw,
  MjmlSection,
  MjmlStyle,
  MjmlText,
  MjmlTitle,
  MjmlWrapper,
} from '@faire/mjml-react';
import { PropsWithChildren } from 'react';

import { emailAssetBaseUrl, emailLogoUrl } from '@encryption/src/server/email/assets';
import { emailPalette } from '@encryption/src/server/email/palette';
import { getEmailStyles, getStorybookStyles } from '@encryption/src/server/email/styles';
import { t } from '@encryption/src/server/i18n';
import { brandFontFaceCss, getServerBrandFont } from '@encryption/src/shared/brand-font';

// Storybook toggles dark mode manually (no media query change), so a dedicated stylesheet
// variant is swapped in. In the browser this expression is statically replaced by the
// Storybook Vite define, so no runtime process reference remains after bundling.
const isStorybookEnvironment: boolean = process.env.STORYBOOK_ENVIRONMENT === 'true';

export interface StandardLayoutProps {
  locale: string;
  title: string;
}

export function StandardLayout(props: PropsWithChildren<StandardLayoutProps>) {
  const currentYear = new Date().getFullYear();

  return (
    <Mjml>
      <MjmlHead>
        <MjmlTitle>{props.title}</MjmlTitle>
        <MjmlAttributes>
          <MjmlSection padding="10px 0px"></MjmlSection>
          <MjmlColumn padding="0px 0px"></MjmlColumn>
          {/* Colours come from the email palette (one patch point per instance). 8px
              button radius. */}
          <MjmlDivider css-class="divider" border-width="1px" border-color={emailPalette.dividerLight}></MjmlDivider>
          <MjmlAll fontFamily={emailPalette.fontFamily}></MjmlAll>
          <MjmlText cssClass="body-text" color={emailPalette.bodyTextLight} fontSize="14px" lineHeight="24px"></MjmlText>
          <MjmlButton
            backgroundColor={emailPalette.brandPrimary}
            borderRadius="8px"
            cssClass="email-button"
            color={emailPalette.onBrand}
            fontSize={16}
            fontWeight="500"
            lineHeight="24px"
            padding="10px 20px"
          ></MjmlButton>
        </MjmlAttributes>
        <MjmlStyle>{brandFontFaceCss(getServerBrandFont(), emailAssetBaseUrl())}</MjmlStyle>
        <MjmlStyle>{isStorybookEnvironment ? getStorybookStyles() : getEmailStyles()}</MjmlStyle>
        <MjmlRaw>
          {!isStorybookEnvironment && (
            <>
              <meta name="color-scheme" content="light dark" />
              <meta name="supported-color-schemes" content="light dark" />
            </>
          )}
        </MjmlRaw>
      </MjmlHead>
      <MjmlBody width={500}>
        <MjmlWrapper fullWidth cssClass="body-wrapper" backgroundColor={emailPalette.lightBody}>
          <MjmlSection cssClass="logo-section">
            <MjmlGroup>
              <MjmlColumn verticalAlign="middle">
                <MjmlImage
                  cssClass="logo-light"
                  src={emailLogoUrl('logo.png')}
                  alt="La Suite numérique"
                  width="150px"
                  align="center"
                  padding="8px 0px"
                />
                <MjmlImage
                  cssClass="logo-dark"
                  src={emailLogoUrl('logo-dark.png')}
                  alt="La Suite numérique"
                  width="150px"
                  align="center"
                  padding="8px 0px"
                />
              </MjmlColumn>
            </MjmlGroup>
          </MjmlSection>
          <MjmlSection cssClass="content-card" backgroundColor={emailPalette.lightCard}>
            <MjmlGroup>
              <MjmlColumn>{props.children}</MjmlColumn>
            </MjmlGroup>
          </MjmlSection>
          <MjmlSection>
            <MjmlGroup>
              <MjmlColumn>
                {/* Names the feature (translated, matching the sender name) so the reader
                    knows which La Suite service the email is about, next to the copyright. */}
                <MjmlText align="center" color={emailPalette.footerText} fontSize={12} paddingTop={2} paddingBottom={0}>
                  {t(props.locale, 'emails.serviceName')} · {currentYear} © LaSuite
                </MjmlText>
              </MjmlColumn>
            </MjmlGroup>
          </MjmlSection>
        </MjmlWrapper>
      </MjmlBody>
    </Mjml>
  );
}
