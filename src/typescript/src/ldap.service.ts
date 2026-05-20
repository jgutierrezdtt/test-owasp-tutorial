// src/typescript/src/ldap.service.ts
// PASO 30: LDAP Injection — escapar metacaracteres de filtros LDAP

import { Injectable } from '@nestjs/common';

function escapeLdapFilter(input: string): string {
  return input
    .replace(/\\/g, '\\5c')
    .replace(/\*/g, '\\2a')
    .replace(/\(/g, '\\28')
    .replace(/\)/g, '\\29')
    .replace(/\0/g, '\\00');
}

@Injectable()
export class LdapService {
  private readonly directory = [
    { uid: 'alice', userPassword: 'pass1', cn: 'Alice Smith', role: 'user' },
    { uid: 'admin', userPassword: 'adminpass', cn: 'Admin User', role: 'admin' },
  ];

  private search(filter: string): Array<Record<string, string>> {
    const matchUid = filter.match(/\(uid=([^)]*)\)/);
    const matchPass = filter.match(/\(userPassword=([^)]*)\)/);
    if (!matchUid || !matchPass) return [];
    return this.directory.filter(
      e => e.uid === matchUid[1] && e.userPassword === matchPass[1],
    );
  }

  async authenticate(username: string, password: string): Promise<boolean> {
    const safeUser = escapeLdapFilter(username);
    const safePass = escapeLdapFilter(password);
    const filter = `(&(uid=${safeUser})(userPassword=${safePass}))`;
    const results = this.search(filter);
    return results.length > 0;
  }
}
