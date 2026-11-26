import type { FastifyInstance } from 'fastify';
import { serializerCompiler, validatorCompiler } from 'fastify-type-provider-zod';

/**
 * Make Fastify validate requests and serialize responses with Zod, so a route's
 * `schema` is enforced at runtime by Fastify itself rather than by a
 * hand-written `.parse()` in the handler. Those same schemas are what
 * `npm run api:schema:generate` turns into the OpenAPI document.
 *
 * Call once at the top of a route plugin, before its routes are defined: it
 * applies to that encapsulated context only. Setting it per plugin (rather than
 * globally) keeps each route self-contained, so it behaves identically in the
 * real server and in the bare Fastify apps the route tests build.
 */
export function configureZodValidation(app: FastifyInstance): void {
  app.setValidatorCompiler(validatorCompiler);
  app.setSerializerCompiler(serializerCompiler);
}
