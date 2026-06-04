    def get_package_installation_targets(self, session_id, policy_package_name):
        """
        Dado el nombre de un Policy Package (tag), busca recursivamente en los ADOMs 
        y devuelve los equipos, sus VDOMs y el ADOM al que pertenecen.
        """
        # 1. Obtener la lista de todos los ADOMs activos para buscar el paquete
        adoms_res = self._request("get", "/dvmdb/adom", session_id=session_id)
        adoms = [adom["name"] for adom in adoms_res.get("result", [{}])[0].get("data", [])]
        
        targets_encontrados = []
        
        # 2. Recorrer los ADOMs buscando el paquete de políticas específico
        for adom in adoms:
            endpoint = f"/pm/config/adom/{adom}/pkg/{policy_package_name}/installation target"
            
            res = self._request("get", endpoint, session_id=session_id)
            
            # Validamos si la respuesta contiene datos válidos para ese paquete en este ADOM
            result_list = res.get("result", [])
            if not result_list or "data" not in result_list[0]:
                continue  # Si no existe el paquete en este ADOM, pasamos al siguiente
                
            data = result_list[0]["data"]
            
            # 3. Parsear los miembros asignados (Scope Members)
            for item in data:
                scope_members = item.get("scope member", [])
                for member in scope_members:
                    # FortiManager suele estructurar el name como 'Dispositivo' o 'Dispositivo-VDOM'
                    name_parts = member.get("name", "").split("-")
                    device_name = name_parts[0]
                    vdom_name = name_parts[1] if len(name_parts) > 1 else "root"
                    
                    # Guardamos la relación completa estructurada
                    targets_encontrados.append({
                        "adom": adom,
                        "device": member.get("name", device_name), # Nombre completo registrado
                        "vdom": member.get("vdom", vdom_name)       # VDOM asignado
                    })
            
            # Si ya encontramos los targets en un ADOM, podemos romper el bucle 
            # (asumiendo que los nombres de paquetes son únicos globales)
            if targets_encontrados:
                break
                
        return targets_encontrados
