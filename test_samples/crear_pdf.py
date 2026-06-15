import os

def crear_pdf_anomalo():
    nombre_archivo = "pdf_anomalo_test.pdf"
    
    # 1. Estructura básica mínima de un PDF válido en texto plano
    pdf_base = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n"
        b"xref\n0 4\n0000000000 65535 f\n0000000009 00000 n\n0000000056 00000 n\n0000000111 00000 n\n"
        b"trailer\n<< /Size 4 /Root 1 0 R >>\n"
        b"startxref\n185\n"
        b"%%EOF\n"
    )
    
    # 2. Inyección de Anomalía: Añadimos datos basura simulando un exploit de desbordamiento o evasión,
    # seguido de marcas %%EOF duplicadas para romper la coherencia de los analizadores tradicionales.
    datos_evasion = (
        b"\n#--- SIMULACION DE INYECCION EXTRA ---#\n"
        b"trailer\n<< /Size 9999 /Root 9999 0 R /Prev 185 >>\n"
        b"startxref\n999999\n"
        b"%%EOF\n"
        b"%%EOF\n"
    )
    
    with open(nombre_archivo, "wb") as f:
        f.write(pdf_base + datos_evasion)
        
    print(f"¡Éxito! Archivo '{nombre_archivo}' generado para pruebas.")
    print("Contiene: Estructuras de tráiler duplicadas y múltiples marcas %%EOF.")

if __name__ == "__main__":
    crear_pdf_anomalo()