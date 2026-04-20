# Cuaderno de Ataques — Corte 3
## Sistema de Clínica Veterinaria

**Matrícula:** 243827  
**Fecha:** Abril 2026

---

## Sección 1 — Tres ataques de SQL Injection

### Ataque 1: Login Bypass (Classic Authentication Bypass)

**Objetivo:** Entrar al sistema sin credenciales válidas manipulando una query de autenticación.

**Escenario vulnerable (código que NO usamos):**
```javascript
// ❌ VULNERABLE — concatenación directa del input
const query = `SELECT * FROM veterinarios WHERE nombre = '${req.body.nombre}'`;
```

**Payload del ataque:**
```
nombre: ' OR '1'='1' --
```

**Query resultante (maliciosa):**
```sql
SELECT * FROM veterinarios WHERE nombre = '' OR '1'='1' --'
```

**Resultado sin protección:**  
La condición `'1'='1'` es siempre verdadera → devuelve todos los registros → el atacante entra como el primer usuario.

**Cómo lo protegemos:**
```javascript
// ✅ PROTEGIDO — parámetro $1 separado del SQL
const result = await client.query(
  'SELECT * FROM veterinarios WHERE nombre = $1',
  [req.body.nombre]
);
```
El driver `pg` envía el valor como parámetro binario separado. PostgreSQL lo trata como dato, nunca como SQL. El `' OR '1'='1'` se busca literalmente como nombre — no existe → devuelve 0 filas.

**Validación Zod adicional:**
```typescript
const schema = z.object({ nombre: z.string().min(1).max(100) });
```

---

### Ataque 2: UNION-Based Injection (Extracción de datos)

**Objetivo:** Usar UNION para extraer datos de otras tablas a través de un endpoint de búsqueda.

**Escenario vulnerable (código que NO usamos):**
```javascript
// ❌ VULNERABLE — q se concatena directamente
const query = `SELECT id, nombre FROM mascotas WHERE nombre ILIKE '%${req.query.q}%'`;
```

**Payload del ataque:**
```
q: %' UNION SELECT id, cedula FROM veterinarios --
```

**Query resultante (maliciosa):**
```sql
SELECT id, nombre FROM mascotas WHERE nombre ILIKE '%%' 
UNION SELECT id, cedula FROM veterinarios --'%'
```

**Resultado sin protección:**  
La respuesta incluiría cédulas profesionales de los veterinarios mezcladas con los nombres de mascotas — fuga de datos confidenciales.

**Cómo lo protegemos:**
```javascript
// ✅ PROTEGIDO — el % se construye en JS, el valor completo va como $1
const termino = `%${q}%`;
const result = await client.query(
  'SELECT id, nombre FROM mascotas WHERE nombre ILIKE $1',
  [termino]
);
```
El valor `%' UNION SELECT id, cedula FROM veterinarios --` se busca textualmente como nombre de mascota. No hay ninguna mascota con ese nombre → devuelve 0 filas. No hay inyección porque el SQL y el dato están completamente separados.

---

### Ataque 3: Time-Based Blind Injection (Inferencia por tiempo)

**Objetivo:** Confirmar vulnerabilidad y extraer datos bit a bit midiendo tiempos de respuesta, sin ver resultados directos.

**Escenario vulnerable (código que NO usamos):**
```javascript
// ❌ VULNERABLE
const query = `SELECT * FROM mascotas WHERE id = ${req.params.id}`;
```

**Payload del ataque:**
```
id: 1; SELECT pg_sleep(5) --
```

**Query resultante (maliciosa):**
```sql
SELECT * FROM mascotas WHERE id = 1; SELECT pg_sleep(5) --
```

**Resultado sin protección:**  
La respuesta tarda 5 segundos → el atacante confirma que la inyección funciona. Con variantes como:
```sql
1; SELECT CASE WHEN (SELECT COUNT(*) FROM veterinarios) > 3 THEN pg_sleep(5) ELSE pg_sleep(0) END --
```
puede extraer información lógica midiendo si la respuesta tarda o no.

**Cómo lo protegemos:**
```javascript
// ✅ PROTEGIDO — id validado como entero por Zod antes de llegar a la query
const schema = z.object({ id: z.coerce.number().int().positive() });
const { id } = schema.parse(req.params);

const result = await client.query(
  'SELECT * FROM mascotas WHERE id = $1',
  [id]
);
```
Zod rechaza el string `"1; SELECT pg_sleep(5) --"` porque no es un entero válido → error 400 antes de tocar la base de datos. Incluso si pasara, el paramétrico no permite múltiples statements.

---

## Sección 2 — Demostración de Row-Level Security

### Configuración

La tabla `vet_atiende_mascota` define qué veterinario atiende a cada mascota:
- **vet_id=1 (Dr. López):** Firulais (1), Toby (5), Max (7) — 3 mascotas
- **vet_id=2 (Dra. García):** Misifú (2), Luna (4), Dante (9) — 3 mascotas
- **vet_id=3 (Dr. Méndez):** Rocky (3), Pelusa (6), Coco (8), Mango (10) — 4 mascotas

### Demostración

**Paso 1 — Como Dr. López (vet_id=1):**
```sql
SET app.current_vet_id = '1';
SET ROLE veterinario;
SELECT id, nombre FROM mascotas ORDER BY id;
```
```
 id | nombre
----+----------
  1 | Firulais
  5 | Toby
  7 | Max
(3 rows)
```

**Paso 2 — Como Dra. García (vet_id=2):**
```sql
SET app.current_vet_id = '2';
SET ROLE veterinario;
SELECT id, nombre FROM mascotas ORDER BY id;
```
```
 id | nombre
----+--------
  2 | Misifú
  4 | Luna
  9 | Dante
(3 rows)
```

**Paso 3 — Como administrador (BYPASSRLS):**
```sql
SET ROLE administrador;
SELECT id, nombre FROM mascotas ORDER BY id;
```
```
 id |  nombre
----+----------
  1 | Firulais
  2 | Misifú
  3 | Rocky
  4 | Luna
  5 | Toby
  6 | Pelusa
  7 | Max
  8 | Coco
  9 | Dante
 10 | Mango
(10 rows)
```

**Conclusión:** El mismo `SELECT * FROM mascotas` devuelve 3, 3 o 10 filas dependiendo del rol y el `app.current_vet_id` activo. El filtro ocurre dentro de PostgreSQL — el código de la API no necesita añadir `WHERE vet_id = ?` manualmente.

---

## Sección 3 — Demostración de Caché Redis

### Configuración

- **Clave:** `vacunacion:pendiente`
- **TTL:** 60 segundos
- **Estrategia:** Cache-Aside
- **Invalidación:** `redis.del('vacunacion:pendiente')` en `POST /vacunas`

### Demostración

**Request 1 — Cache MISS (datos frescos de PostgreSQL):**
```bash
curl -I http://localhost:4000/vacunacion-pendiente
```
```
X-Cache: MISS
```
Log del servidor:
```
[Redis] MISS — vacunacion:pendiente
```
Tiempo de respuesta: ~12ms (consulta a PostgreSQL)

**Request 2 — Cache HIT (datos desde Redis):**
```bash
curl -I http://localhost:4000/vacunacion-pendiente
```
```
X-Cache: HIT
```
Log del servidor:
```
[Redis] HIT — vacunacion:pendiente
```
Tiempo de respuesta: ~2ms (Redis en memoria local)

**Request 3 — Invalidación al aplicar vacuna:**
```bash
curl -X POST http://localhost:4000/vacunas \
  -H "Content-Type: application/json" \
  -d '{"mascota_id":10,"vacuna_id":1,"veterinario_id":3,"costo_cobrado":350}'
```
Log del servidor:
```
[Redis] Cache invalidado: vacunacion:pendiente
```

**Request 4 — Nuevo MISS tras invalidación:**
```bash
curl -I http://localhost:4000/vacunacion-pendiente
```
```
X-Cache: MISS
```
El ciclo se reinicia: datos frescos de PostgreSQL → guardados en Redis → próximos 60s son HIT.

### Observación en el Frontend

En la pantalla de Vacunación del frontend, el banner superior cambia de color:
- 🟢 **Verde: "Cache HIT"** — datos servidos desde Redis  
- 🟠 **Naranja: "Cache MISS"** — datos consultados desde PostgreSQL  

Al presionar "Refrescar" repetidamente se observa HIT; al esperar 60 segundos o aplicar una vacuna, el siguiente request muestra MISS.
