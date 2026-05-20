# Paso 8 — Insecure Randomness
**Tecnologia:** Java / Spring Boot | **OWASP:** A02:2021 - Cryptographic Failures | **CWE-338**

---

## Que es esta vulnerabilidad?

Insecure Randomness ocurre cuando una aplicacion usa un generador de numeros pseudoaleatorios (PRNG) debil para producir valores de seguridad como tokens de reset de contrasena, codigos de verificacion, session IDs o claves temporales. Los PRNGs como `java.util.Random` son deterministicos: dado el estado inicial (seed), toda la secuencia de valores futuros es predecible.

`java.util.Random` usa un algoritmo lineal congruencial (LCG) cuyo estado interno tiene 48 bits. Con solo 2-3 tokens observados, un atacante puede calcular el estado interno del generador y predecir todos los tokens futuros. En un sistema con miles de usuarios, la probabilidad de predecir un token valido es muy alta.

La consecuencia directa es la toma de cuenta (account takeover): el atacante puede solicitar reset de contrasena para cualquier usuario y, conociendo el algoritmo, calcular el token que el servidor enviara por email antes de que la victima lo reciba.

---

## Donde ocurre en este codigo?

**Archivo:** `src/java/src/main/java/com/example/api/controller/TokenController.java`

```java
// CODIGO VULNERABLE — estado actual del ejercicio
private final Random random = new Random();  // PRNG predecible

@PostMapping("/reset-password")
public ResponseEntity<?> requestReset(@RequestParam String email) {
    String token = String.valueOf(random.nextInt(999999));  // max 6 digitos: 10^6 posibilidades
    saveResetToken(email, token);
    return ResponseEntity.ok(Map.of("message", "Reset email sent"));
}
```

Dos problemas independientes:
1. `Random` es predecible por algoritmo una vez que se conoce el seed.
2. `nextInt(999999)` produce tokens de hasta 6 digitos decimales: solo 1 millon de valores posibles, atacables por fuerza bruta en minutos si el servidor no tiene rate limiting.

---

## Como lo explotaria un atacante

**Prediccion de tokens via estado interno del PRNG:**
```python
# El atacante solicita resets para cuentas propias y observa 3 tokens
tokens_observed = [482913, 731204, 298847]

# Herramientas como "java-random-cracker" invierten el LCG en segundos
# y recuperan el estado interno de 48 bits
seed = crack_random_seed(tokens_observed)

# Con el seed, predecir el siguiente token para la cuenta victima
r = JavaRandom(seed)
predicted_token = r.next_int(999999)
print(f"Token predicho: {predicted_token}")
```

**Fuerza bruta de 6 digitos:**
Con solo 1.000.000 de valores posibles y sin rate limiting, un atacante puede probar todos en minutos.

**Timing attack en el reset:**
Si el servidor procesa el reset sin expirar el token rapidamente, el atacante tiene una ventana de tiempo amplia para la prediccion o fuerza bruta.

---

## Tu tarea: aplicar la mitigacion

Modifica `TokenController.java` para usar `SecureRandom` con entropia suficiente:

```java
// CODIGO SEGURO
import java.security.SecureRandom;
import java.util.Base64;

private final SecureRandom secureRandom = new SecureRandom();

@PostMapping("/reset-password")
public ResponseEntity<?> requestReset(@RequestParam String email) {
    byte[] tokenBytes = new byte[32];  // 256 bits de entropia
    secureRandom.nextBytes(tokenBytes);
    String token = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
    // token tiene ~43 caracteres URL-safe, imposible de predecir o forzar bruta
    saveResetToken(email, token);
    return ResponseEntity.ok(Map.of("message", "Reset email sent"));
}
```

### Por que funciona esta mitigacion?

- **`SecureRandom`:** usa fuentes de entropia del sistema operativo (`/dev/urandom` en Linux, `CryptGenRandom` en Windows). No es deterministico: no hay seed conocido ni algoritmo que permita predecir valores futuros a partir de valores observados.
- **32 bytes (256 bits) de entropia:** con 2^256 posibilidades, la fuerza bruta es computacionalmente infeasible incluso con hardware especializado.
- **Base64 URL-safe:** codifica los 32 bytes en caracteres seguros para URLs y emails, produciendo tokens de 43 caracteres. La codificacion no reduce la entropia.

---

## Variantes de la misma categoria (Cryptographic Failures — mas complejas)

### Variante A: IV predecible en AES-CBC

Cifrar con AES-CBC usando un IV predecible o reutilizado expone el plaintext:

```java
// VULNERABLE — IV derivado de timestamp predecible
public byte[] encrypt(byte[] data, byte[] key) throws Exception {
    long timestamp = System.currentTimeMillis();  // predecible
    byte[] iv = ByteBuffer.allocate(16).putLong(timestamp).array();  // IV predecible
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
    return cipher.doFinal(data);
}
```

Si el IV es predecible, un atacante que conoce el plaintext de un mensaje cifrado puede montar un ataque de "chosen-plaintext" y deducir el contenido de otros mensajes.

```java
// SEGURO — IV aleatorio criptograficamente fuerte, enviado junto al ciphertext
public byte[] encrypt(byte[] data, byte[] key) throws Exception {
    byte[] iv = new byte[16];
    new SecureRandom().nextBytes(iv);  // IV aleatorio e impredecible
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
    byte[] ciphertext = cipher.doFinal(data);
    // Concatenar IV + ciphertext para que el receptor pueda descifrar
    ByteBuffer result = ByteBuffer.allocate(iv.length + ciphertext.length);
    result.put(iv).put(ciphertext);
    return result.array();
}
```

---

### Variante B: Session ID basado en timestamp

```python
# VULNERABLE — session ID derivado de tiempo y datos predecibles
import time, hashlib

def generate_session_id(user_id: int) -> str:
    seed = f"{user_id}{time.time()}{user_id * 31}"
    return hashlib.md5(seed.encode()).hexdigest()  # predecible si se conoce user_id y tiempo
```

Un atacante que conoce el `user_id` y el tiempo aproximado de login puede generar el mismo session ID.

```python
# SEGURO — session ID con entropia del SO
import secrets

def generate_session_id() -> str:
    return secrets.token_urlsafe(32)  # 32 bytes = 256 bits de entropia del SO
```

---

### Variante C: OTP (One-Time Password) predecible basado en tiempo sin TOTP

```python
# VULNERABLE — OTP basado en Random con seed de tiempo
import random, time

def generate_otp(user_id: int) -> str:
    random.seed(int(time.time()))  # seed predecible
    return str(random.randint(100000, 999999))
```

Dos usuarios que solicitan OTP en el mismo segundo reciben el mismo codigo. El codigo es predecible conociendo el tiempo aproximado.

```python
# SEGURO — usar TOTP estandar (RFC 6238) o secrets del SO
import pyotp  # implementacion TOTP estandar

def generate_totp_secret() -> str:
    return pyotp.random_base32()  # secreto con entropia del SO

def get_current_otp(secret: str) -> str:
    return pyotp.TOTP(secret).now()  # TOTP: derivado de HMAC-SHA1 sobre tiempo Unix
```

---

## Referencias

- [OWASP A02:2021 - Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
- [CWE-338: Use of Cryptographically Weak PRNG](https://cwe.mitre.org/data/definitions/338.html)
- [Java Security - SecureRandom](https://docs.oracle.com/javase/8/docs/api/java/security/SecureRandom.html)
- [NIST SP 800-90A - Random Number Generation](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf)

---

## Lo que valida el workflow automaticamente

El workflow **Validate Step 08** exige que `TokenController.java` contenga:
- `SecureRandom`
- `nextBytes`
- La ausencia de `new Random()`