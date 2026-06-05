########################################
# CGNAT Determinístico - Por pools reales
# Red pública:  192.141.177.250 hacia abajo
# Red privada:  100.75.x.x (todos los pools)
# 32 clientes por IP pública
# 2000 puertos por cliente (1024-65023)
########################################

:local PublicBase      "192.141.177"
:local PublicFirstIP   250
:local ClientsPerPubIP 32
:local PortsPerClient  2000
:local StartPort       1024
:local OutIfList       "mi-wan"

# Formato: "base|oct3inicio|oct3fin|oct4fin"
:local pools {
    "100.75|0|1|255";
    "100.75|2|3|255";
    "100.75|4|4|255";
    "100.75|5|5|255";
    "100.75|6|6|255";
    "100.75|7|7|255";
    "100.75|8|8|255";
    "100.75|9|9|255";
    "100.75|10|10|255";
    "100.75|11|11|255";
    "100.75|12|12|255";
    "100.75|15|15|255"
}

########################################
# Validación
########################################
:if (($StartPort + ($ClientsPerPubIP * $PortsPerClient) - 1) > 65535) do={
    :error "ERROR: overflow de puertos."
}

########################################
# PASADA 1 — construir tabla de bloques
########################################
:local bloques [:toarray ""]
:local globalSlot 0
:local blockStartIP ""
:local blockEndIP ""
:local blockPubIP ""
:local blockNum 1

:foreach poolDef in=$pools do={
    :local p1 [:find $poolDef "|"]
    :local base [:pick $poolDef 0 $p1]
    :local rest [:pick $poolDef ($p1+1) [:len $poolDef]]
    :local p2 [:find $rest "|"]
    :local oct3start [:tonum [:pick $rest 0 $p2]]
    :local rest2 [:pick $rest ($p2+1) [:len $rest]]
    :local p3 [:find $rest2 "|"]
    :local oct3end [:tonum [:pick $rest2 0 $p3]]
    :local oct4end [:tonum [:pick $rest2 ($p3+1) [:len $rest2]]]

    :local oct3 $oct3start
    :while ($oct3 <= $oct3end) do={
        :local oct4max $oct4end
        :if ($oct3 < $oct3end) do={ :set oct4max 255 }

        :for oct4 from=0 to=$oct4max do={
            :local privIP "$base.$oct3.$oct4"
            :local posInBlock ($globalSlot % $ClientsPerPubIP)
            :local pubBlockIdx ($globalSlot / $ClientsPerPubIP)
            :local pubOctet ($PublicFirstIP - $pubBlockIdx)

            :if ($pubOctet < 1) do={
                :error "ERROR: IPs publicas agotadas en $privIP"
            }

            :if ($posInBlock = 0) do={
                :set blockStartIP $privIP
                :set blockPubIP "$PublicBase.$pubOctet"
                :set blockNum ($pubBlockIdx + 1)
            }

            :set blockEndIP $privIP

            :if ($posInBlock = ($ClientsPerPubIP - 1)) do={
                :set bloques ($bloques , "$blockStartIP|$blockEndIP|$blockPubIP|$blockNum")
            }

            :set globalSlot ($globalSlot + 1)
        }
        :set oct3 ($oct3 + 1)
    }
}

# Guardar último bloque si quedó incompleto
:if (($globalSlot % $ClientsPerPubIP) != 0) do={
    :set bloques ($bloques , "$blockStartIP|$blockEndIP|$blockPubIP|$blockNum")
}

:log info "Pasada 1 completa: $[:len $bloques] bloques calculados"

########################################
# PASADA 2 — crear reglas NAT
########################################
:local globalSlot2 0

:foreach poolDef in=$pools do={
    :local p1 [:find $poolDef "|"]
    :local base [:pick $poolDef 0 $p1]
    :local rest [:pick $poolDef ($p1+1) [:len $poolDef]]
    :local p2 [:find $rest "|"]
    :local oct3start [:tonum [:pick $rest 0 $p2]]
    :local rest2 [:pick $rest ($p2+1) [:len $rest]]
    :local p3 [:find $rest2 "|"]
    :local oct3end [:tonum [:pick $rest2 0 $p3]]
    :local oct4end [:tonum [:pick $rest2 ($p3+1) [:len $rest2]]]

    :local oct3 $oct3start
    :while ($oct3 <= $oct3end) do={
        :local oct4max $oct4end
        :if ($oct3 < $oct3end) do={ :set oct4max 255 }

        :for oct4 from=0 to=$oct4max do={
            :local privIP "$base.$oct3.$oct4"
            :local posInBlock ($globalSlot2 % $ClientsPerPubIP)
            :local pubBlockIdx ($globalSlot2 / $ClientsPerPubIP)
            :local pubOctet ($PublicFirstIP - $pubBlockIdx)
            :local pubIP "$PublicBase.$pubOctet"
            :local blockNum2 ($pubBlockIdx + 1)
            :local clientNum ($posInBlock + 1)
            :local portStart ($StartPort + ($posInBlock * $PortsPerClient))
            :local portEnd ($portStart + $PortsPerClient - 1)

            :if ($posInBlock = 0) do={
                :local entry ($bloques->$pubBlockIdx)
                :local e1 [:find $entry "|"]
                :local rangeStart [:pick $entry 0 $e1]
                :local rest3 [:pick $entry ($e1+1) [:len $entry]]
                :local e2 [:find $rest3 "|"]
                :local rangeEnd [:pick $rest3 0 $e2]

                /ip firewall nat add \
                    chain=srcnat \
                    action=jump \
                    jump-target="cgnat-block-$blockNum2" \
                    src-address="$rangeStart-$rangeEnd" \
                    out-interface-list=$OutIfList \
                    comment="CGNAT-bloque-$blockNum2-$rangeStart-$rangeEnd"
            }

            /ip firewall nat add \
                chain="cgnat-block-$blockNum2" \
                action=jump \
                jump-target="cgnat-c-$blockNum2-$clientNum" \
                src-address="$privIP" \
                comment="CGNAT-$privIP"

            # Regla TCP con control de puertos
            /ip firewall nat add \
                chain="cgnat-c-$blockNum2-$clientNum" \
                action=scr-nat \
                protocol=tcp \
                src-address="$privIP" \
                to-addresses="$pubIP" \
                to-ports="$portStart-$portEnd" \
                out-interface-list=$OutIfList \
                comment="CGNAT-$privIP-tcp"

            # Regla UDP con control de puertos
            /ip firewall nat add \
                chain="cgnat-c-$blockNum2-$clientNum" \
                action=scr-nat \
                protocol=udp \
                src-address="$privIP" \
                to-addresses="$pubIP" \
                to-ports="$portStart-$portEnd" \
                out-interface-list=$OutIfList \
                comment="CGNAT-$privIP-udp"

            # Regla fallback — ICMP, ESP, GRE, AH y cualquier otro protocolo
            # Traduce IP pública correcta sin restricción de puertos
            # Trazabilidad por IP pública + syslog externo
            /ip firewall nat add \
                chain="cgnat-c-$blockNum2-$clientNum" \
                action=netmap \
                src-address="$privIP" \
                to-addresses="$pubIP" \
                out-interface-list=$OutIfList \
                comment="CGNAT-$privIP-otros"

            :set globalSlot2 ($globalSlot2 + 1)
        }
        :set oct3 ($oct3 + 1)
    }
}

:log info "CGNAT completado: $globalSlot2 clientes, $[:len $bloques] bloques."
