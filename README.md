# Attack Surface Mapper

Aplicación web standalone para educación y concientización sobre gestión de
superficie de ataque. Permite mapear activos de una organización contra ataques
o técnicas MITRE ATT&CK y calcular un índice visual de riesgo por cruce.

## Uso

Abre `index.html` directamente en el navegador o sirve la carpeta con cualquier
servidor estático. No requiere instalación, dependencias ni backend.

Los datos se guardan en el Web Storage del navegador (`localStorage`). Para
compartir o respaldar un trabajo usa `Exportar proyecto`; para restaurarlo usa
`Importar proyecto`.

Usa `Reiniciar en blanco` para borrar los datos del navegador y dejar la
aplicación sin activos, ataques ni evaluaciones. Usa `Demo completo` para cargar
un escenario reemplazable con la matriz ya evaluada y coloreada.

## Funciones

- Alta, baja y modificación de activos.
- Tipos de activos sugeridos: aplicaciones web, APIs, bases de datos,
  identidades, correo, SaaS, cloud workloads, OT/IoT, terceros, repositorios y
  backups.
- Alta, baja y modificación de ataques.
- Importación de ataques desde MITRE ATT&CK STIX JSON, Navigator layer, CSV o
  texto pegado.
- Matriz de ataques por activos con evaluación por celda.
- Registro de vulnerabilidades, exposición, amenazas activas, controles de
  mitigación e impacto del negocio.
- Puntaje de riesgo de 0 a 100 con umbrales configurables.
- Semáforo: verde para bajo, amarillo para medio, rojo para alto y gris para
  no aplica.
- Reinicio local en blanco y demo completo con matriz coloreada.

## Fórmula

El riesgo inherente pondera vulnerabilidades, exposición, amenazas activas e
impacto de negocio. Los controles de mitigación reducen el resultado. La escala
final se normaliza a un porcentaje entre 0 y 100.
