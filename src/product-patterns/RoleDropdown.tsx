import { AccessRoleDropdown, type DropdownMenuOption } from '@gouvfr-lasuite/ui-components';
import { useState } from 'react';

// The design system's role menu needs its open state from outside, as every
// product row owns it.
export function RoleDropdown({ roles, selectedRole, canUpdate = true }: { roles: DropdownMenuOption[]; selectedRole: string; canUpdate?: boolean }) {
  const [isOpen, setIsOpen] = useState(false);
  const [role, setRole] = useState(selectedRole);

  return (
    <AccessRoleDropdown
      roles={roles}
      selectedRole={role}
      onSelect={setRole}
      isOpen={isOpen}
      onOpenChange={setIsOpen}
      canUpdate={canUpdate}
      canDelete={false}
    />
  );
}
