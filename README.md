# Open OSINT Kit 1.0.1

![Open OSINT Kit: inteligencia de fuentes abiertas](assets/banner.svg)

CLI multiplataforma en Python para investigaciones autorizadas de dominios, infraestructura e indicadores públicos. No necesita paquetes externos.

## Módulos

`domain` reúne RDAP, DNS (A, AAAA, MX, NS, TXT y CAA) vía DNS-over-HTTPS, y certificados de Certificate Transparency. Cada fuente falla de forma independiente.

`ip` consulta RDAP y DNS inverso para una dirección pública. Las IP privadas, locales y reservadas se rechazan.

`ioc` clasifica dominios, IP, URLs HTTP(S) y hashes MD5/SHA1/SHA256, y genera enlaces a servicios públicos como VirusTotal, AlienVault OTX, URLhaus, AbuseIPDB y CIRCL Hashlookup. No envía el indicador automáticamente.

`search` genera enlaces para búsquedas manuales de nombres de usuario u organizaciones en buscadores y fuentes públicas. No rastrea perfiles ni confirma identidades.

## Instalación

Requiere Python 3.9 o posterior y `pip`; la primera instalación necesita conexión a Internet para resolver el backend de construcción. La instalación es para el usuario actual y no necesita privilegios de administrador.

En Windows, desde la raíz del workspace:

```powershell
powershell -ExecutionPolicy Bypass -File .\Osint\install.ps1
osint-kit --help
```

En Linux, desde la raíz del workspace:

```bash
bash Osint/install.sh
osint-kit --help
```

Los instaladores añaden la carpeta de ejecutables al PATH del usuario. En Linux, el programa queda aislado en un entorno virtual bajo `~/.local/share/open-osint-kit`; así no modifica paquetes del sistema. Abre una terminal nueva después de instalar para que el PATH actualizado se aplique a otras sesiones.

```powershell
osint-kit domain example.org
osint-kit domain example.org --output informe.json
osint-kit ip 8.8.8.8 --output ip.json
osint-kit ioc example.org
osint-kit ioc 44d88612fea8a8f36de82e1278abb02f
osint-kit search ejemplo --kind organization
osint-kit search ejemplo_user --kind username --output busqueda.json
```

Requiere Python 3.9 o posterior. `domain` e `ip` requieren conexión a Internet; `ioc` y `search` solo generan enlaces y JSON. El timeout de `domain` e `ip` aplica por fuente, por lo que la ejecución completa puede tardar más que ese valor.

## Uso responsable

Usa el kit solo en investigaciones legítimas y autorizadas. Las únicas consultas automáticas son RDAP, Cloudflare DNS y `crt.sh` para dominios/IP indicados; no escanea puertos, no intenta autenticarse ni explota sistemas. `ioc` y `search` muestran enlaces que el usuario decide abrir. No incluyas URLs con query string: se rechazan para reducir el riesgo de exponer tokens o secretos. Los datos públicos pueden ser incompletos, antiguos o estar sujetos a términos de uso; verifica los hallazgos antes de tomar decisiones.
