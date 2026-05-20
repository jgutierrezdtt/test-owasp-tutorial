# Paso 29 — Mass Assignment
**Tecnologia:** TypeScript / NestJS | **OWASP:** A01:2021 - Broken Access Control | **CWE-915**

---

## Que es esta vulnerabilidad?

Mass Assignment ocurre cuando una aplicacion web vincula automaticamente los campos de un objeto del request HTTP a los campos de un modelo o entidad de base de datos, sin filtrar que campos el usuario tiene permiso de modificar. El atacante puede enviar campos extra en el JSON del request (como `isAdmin: true`, `role: "admin"`, `balance: 999999`) que el servidor acepta y aplica porque "mergeea" todo el body en el objeto.

Este patron fue popularizado por Ruby on Rails antes de la proteccion con `attr_accessible`. El CVE-2012-2660 en GitHub (entonces en Rails) permitia a cualquier usuario anadir su clave SSH publica a cualquier repositorio de GitHub. Despues de ese incidente, los frameworks modernos requieren declaracion explicita de campos permitidos.

En NestJS, `@Body() body: any` acepta cualquier campo del JSON del request. Sin un DTO (Data Transfer Object) que declare exactamente que campos se esperan, campos como `isAdmin`, `role`, o `balance` pueden pasar silenciosamente al objeto de persistencia.

---

## Donde ocurre en este codigo?

**Archivo:** `src/typescript/src/profile.controller.ts`

```typescript
// CODIGO VULNERABLE — estado actual del ejercicio
@Put('/profile')
async updateProfile(
  @Request() req: any,
  @Body() body: any,  // acepta cualquier campo sin restriccion
): Promise<{ message: string }> {
  const userId = req.user?.id ?? 'user-1';
  Object.assign(this.users[userId], body);  // copia TODO el body al objeto de usuario
  return { message: 'Perfil actualizado' };
}
```

El objeto de usuario tiene `{id, username, email, isAdmin: false, role: 'user'}`. Con `Object.assign(user, body)`, si `body` contiene `{isAdmin: true, role: 'admin'}`, esos campos se copian al usuario.

---

## Como lo explotaria un atacante

**Escalada de privilegios a administrador:**
```json
PUT /users/profile
Content-Type: application/json

{
  "displayName": "Alice Updated",
  "isAdmin": true,
  "role": "admin"
}
```

El servidor actualiza `displayName` (campo legitimo) pero tambien `isAdmin` y `role`. Alice es ahora administradora.

**Modificacion del balance de cuenta:**
```json
{
  "email": "alice@example.com",
  "balance": 1000000,
  "creditLimit": 50000
}
```

**Tomar control de otra cuenta (si el ID de usuario esta en el body):**
```json
{
  "email": "attacker@example.com",
  "id": "user-admin-id-123"
}
```

Si el codigo hace `Object.assign(targetUser, body)` y `targetUser` se carga via `req.user.id`, pero luego el DAO actualiza usando `body.id`, el atacante puede cambiar el ID efectivo del update.

---

## Tu tarea: aplicar la mitigacion

Modifica `src/typescript/src/profile.controller.ts` para declarar un DTO que permite solo campos especificos:

```typescript
// CODIGO SEGURO
import { Body, Controller, Put, Request } from '@nestjs/common';
import { IsEmail, IsOptional, IsString, MaxLength, MinLength } from 'class-validator';
import { instanceToPlain } from 'class-transformer';

// DTO que declara EXACTAMENTE que campos puede actualizar el usuario
// Campos como isAdmin, role, id, balance no estan aqui y son ignorados
class UpdateProfileDto {
  @IsOptional()
  @IsString()
  @MinLength(1)
  @MaxLength(50)
  displayName?: string;

  @IsOptional()
  @IsEmail()
  email?: string;

  @IsOptional()
  @IsString()
  @MaxLength(200)
  bio?: string;
}

@Controller('users')
export class ProfileController {
  private readonly users: Record<string, Record<string, unknown>> = {
    'user-1': { id: 'user-1', username: 'alice', email: 'alice@example.com', isAdmin: false, role: 'user' },
    'user-2': { id: 'user-2', username: 'bob', email: 'bob@example.com', isAdmin: false, role: 'user' },
  };

  @Put('/profile')
  async updateProfile(
    @Request() req: any,
    @Body() dto: UpdateProfileDto,  // NestJS valida el tipo automaticamente con ValidationPipe global
  ): Promise<{ message: string }> {
    const userId = req.user?.id ?? 'user-1';
    // instanceToPlain serializa solo las propiedades declaradas en el DTO
    // isAdmin, role, id y cualquier otro campo extra son omitidos
    const safeFields = instanceToPlain(dto);
    Object.assign(this.users[userId], safeFields);
    return { message: 'Perfil actualizado' };
  }
}
```

### Por que funciona esta mitigacion?

- **DTO tipado con class-validator:** `UpdateProfileDto` es una clase con decoradores de validacion. Solo tiene tres campos: `displayName`, `email`, `bio`. Cualquier otro campo del JSON del request es ignorado por NestJS al deserializar en una instancia del DTO.
- **`instanceToPlain`:** convierte la instancia del DTO a un objeto plano conteniendo solo las propiedades declaradas en la clase. Aunque el atacante haya enviado `isAdmin: true`, ese campo no existe en `UpdateProfileDto` y no aparece en el objeto resultante de `instanceToPlain`.
- **`ValidationPipe` global en NestJS:** al configurar `app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }))`, NestJS rechaza automaticamente cualquier peticion con campos no declarados en el DTO. `whitelist: true` elimina campos extra silenciosamente; `forbidNonWhitelisted: true` devuelve `400 Bad Request`.

---

## Variantes de la misma categoria (Mass Assignment — otros frameworks)

### Variante A: Mass Assignment en Django con ModelSerializer

```python
# VULNERABLE — DRF ModelSerializer sin campos restringidos
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'  # expone TODOS los campos del modelo incluyendo is_staff

@api_view(['PUT'])
def update_profile(request):
    serializer = UserSerializer(request.user, data=request.data, partial=True)
    if serializer.is_valid():
        serializer.save()  # puede actualizar is_staff, is_superuser, etc.
```

```python
# SEGURO — declarar explicitamente los campos permitidos
class UpdateProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email']  # solo campos seguros
        # is_staff, is_superuser, password NO estan en esta lista

@api_view(['PUT'])
def update_profile(request):
    serializer = UpdateProfileSerializer(request.user, data=request.data, partial=True)
    if serializer.is_valid():
        serializer.save()
```

---

### Variante B: Mass Assignment en Spring Boot con @RequestBody sin @JsonIgnore

```java
// VULNERABLE — entidad JPA usada directamente como @RequestBody
@Entity
public class User {
    @Id private Long id;
    private String email;
    @JsonProperty(access = JsonProperty.Access.READ_ONLY)  // esto no protege en writes
    private boolean isAdmin;  // Jackson puede setear este campo desde el JSON
}

@PutMapping("/profile")
public User updateProfile(@RequestBody User user) {
    return userRepository.save(user);  // persiste isAdmin si vino en el JSON
}
```

```java
// SEGURO — DTO separado de la entidad JPA; mapear manualmente solo campos permitidos
public record UpdateProfileRequest(String email, String displayName) {}

@PutMapping("/profile")
public User updateProfile(@RequestBody UpdateProfileRequest req,
                          @AuthenticationPrincipal User currentUser) {
    currentUser.setEmail(req.email());
    currentUser.setDisplayName(req.displayName());
    // isAdmin no se puede cambiar porque no esta en UpdateProfileRequest
    return userRepository.save(currentUser);
}
```

---

### Variante C: Mass Assignment en GraphQL mutations

```graphql
# VULNERABLE — mutation que acepta cualquier campo del tipo User
type Mutation {
  updateUser(input: UserInput!): User
}
input UserInput {
  email: String
  displayName: String
  isAdmin: Boolean    # el cliente puede enviar este campo
  role: String        # y este
}
```

```graphql
# SEGURO — mutation con input type que solo expone campos editables por el usuario
type Mutation {
  updateMyProfile(input: UpdateProfileInput!): User
}
input UpdateProfileInput {
  email: String       # el usuario puede cambiar su email
  displayName: String # y su nombre de pantalla
  # isAdmin y role NO estan en este input type
  # Los admins tienen su propia mutation protegida por roles
}
```

---

## Referencias

- [OWASP A01:2021 - Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)
- [OWASP Mass Assignment Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)
- [GitHub Mass Assignment (Rails CVE-2012-2660)](https://github.blog/2012-03-04-public-key-security-vulnerability-and-mitigation/)

---

## Lo que valida el workflow automaticamente

El workflow **Validate Step 29** exige que `src/typescript/src/profile.controller.ts` contenga:
- `UpdateProfileDto`
- `instanceToPlain`
- La ausencia de `@Body() body: any`
