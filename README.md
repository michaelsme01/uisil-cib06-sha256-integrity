# Validador de Integridad y Forense de Archivos (SHA-256)

Proyecto práctico desarrollado para el curso **CIB-06 Criptografía II: Aplicaciones** de la Maestría Profesional en Ciberseguridad (UISIL).

## Descripción de la Solución
Aplicación de escritorio interactiva desarrollada en Python para la comprobación determinista de integridad de datos mediante el algoritmo criptográfico SHA-256 (256 bits / 64 caracteres hexadecimales). Permite contrastar archivos contra hashes de referencia o comparar dos archivos de manera simultánea, incluyendo una tabla de metadatos forenses (nombre, tamaño, tipo y fechas) y la integración de consultas dinámicas de reputación en VirusTotal.

## Arquitectura del Proyecto
* **`CryptoEngine` (Módulo Criptográfico):** Lectura de archivos en bloques (*chunks*) de 64 KB para optimizar la memoria y cálculo del digesto SHA-256 mediante `hashlib`.
* **`FileMetadata` (Extracción Forense):** Obtención de atributos del sistema de archivos (`os.stat`) para análisis de propiedades básicas.
* **`IntegrityApp` (Capa de Presentación y Lógica):** Interfaz gráfica (`tkinter`) para la carga de archivos, evaluación comparativa de integridad y apertura del reporte web en VirusTotal.

## Requisitos y Ejecución
* Python 3.8 o superior.
* Soporte gráfico estándar (`python3-tk`).

```bash
# Ejecución en Linux/Windows
python3 integrity_checker.py
