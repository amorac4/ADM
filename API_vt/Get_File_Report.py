import requests      # type: ignore
import json 

# Clase que obtiene el reporte de un archivo en VirusTotal
class VirusTotalReporter:

    def get_report(self, apikey, hash):
        """
        Obtiene el reporte de un archivo en VirusTotal.

        :param apikey: Tu API key de VirusTotal.
        :param hash: El hash del archivo que deseas analizar.
        :return: El reporte en formato JSON formateado o un mensaje de error.
        """
        print("Obteniendo reporte...")
        
        # Construye la URL para la solicitud
        url = f"https://www.virustotal.com/api/v3/files/{hash}"
        
        # Configura los headers con la API key
        headers = {
            "accept": "application/json",
            "x-apikey": apikey
        }
        
        try:
            # Realiza la solicitud GET a la API de VirusTotal
            response = requests.get(url, headers=headers)
            
            # Verifica si la solicitud fue exitosa
            if response.status_code == 200:
                # Formatea el JSON con indentación y ordena las claves
                ReporteF = json.dumps(response.json(), indent=4, sort_keys=True)
                return ReporteF  # Retorna el reporte en formato JSON formateado
            else:
                return f"Error: {response.status_code} - {response.text}"
        
        except requests.exceptions.RequestException as e:
            return f"Error en la solicitud: {e}"


if __name__ == "__main__":
    # Solicita la API key y el hash al usuario
    apikey = input("Ingrese su API Key: ")
    hash = input("Ingrese el hash del archivo: ")
    
    # Crea una instancia de la clase y obtiene el reporte
    vt_reporter = VirusTotalReporter()
    report = vt_reporter.get_report(apikey, hash)
    
    # Guarda el reporte en un archivo .txt
    if not report.startswith("Error"):  # Solo guarda si no hay errores
        archivo = f"report_{hash}.txt"  # Nombre del archivo basado en el hash
        with open(archivo, "w") as file:
            file.write(report)
        print(f"Reporte guardado en '{archivo}'.")
    else:
        print(report)  # Muestra el mensaje de error en la consola