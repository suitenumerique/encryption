interface NamedUser {
  firstName: string | null;
  lastName: string | null;
}

/**
 * How a user is named to the people they share with: their first and last names
 * as the provider last gave them, or null until they have signed in since names
 * were stored (the interface then shows their email instead).
 */
export function userFullName(user: NamedUser): string | null {
  const name = [user.firstName, user.lastName]
    .filter((part): part is string => part !== null && part.trim().length > 0)
    .join(' ')
    .trim();

  return name.length > 0 ? name : null;
}

/** A user as an email names them to someone else: their name, else their address. */
export function userLabel(user: NamedUser & { email: string }): string {
  return userFullName(user) ?? user.email;
}

/**
 * The same, with the address in brackets, for an email that asks the reader to
 * decide or tells them who reached their data: a name alone can be borne by
 * someone else, the address says which account it is.
 */
export function userLabelWithEmail(user: NamedUser & { email: string }): string {
  const name = userFullName(user);

  return name === null ? user.email : `${name} (${user.email})`;
}
