# Borrar todas las reglas CGNAT

:local rules [/ip firewall nat find comment~"CGNAT"]
:local total [:len $rules]
:local count 0

:log info "Borradas $total reglas CGNAT. Iniciando..."

:foreach r in=$rules do={
    /ip firewall nat remove $r
    :set count ($count + 1)
    :if (($count % 100) = 0) do={
        :log info "Progreso: $count de $total..."
    }
}

:log info "Listo: $count reglas CGNAT eliminadas."
