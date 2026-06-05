########################################
# CGNAT Determinístico - Parámetros
########################################
:local TotalClients 200
:local FirstPublicIP 8
:local PublicBase "200.43.43"
:local PrivateBase "100.76"
:local ClientsPerPublicIP 32
:local PortsPerClient 2000
:local StartingPort 1024
:local OutInterfaceList "mi-wan"

########################################
# Delays (ajustables según carga)
########################################
:local delay_entre_reglas 20ms
:local delay_entre_clientes 50ms
:local delay_entre_bloques 2s

########################################
# Cálculo automático
########################################
:local totalPublicIPs (($TotalClients + $ClientsPerPublicIP - 1) / $ClientsPerPublicIP)

:local privOctet3 0
:local privOctet4 1
:local currentPublicIP $FirstPublicIP
:local blockNum 1

:for block from=1 to=$totalPublicIPs do={

    :local clientsThisBlock $ClientsPerPublicIP
    :local processed (($block - 1) * $ClientsPerPublicIP)
    :local remaining ($TotalClients - $processed)
    :if ($remaining < $ClientsPerPublicIP) do={
        :set clientsThisBlock $remaining
    }

    :local pubAddr "$PublicBase.$currentPublicIP"
    :local privStart "$PrivateBase.$privOctet3.$privOctet4"
    :local endOctet4 ($privOctet4 + $clientsThisBlock - 1)
    :local endOctet3 $privOctet3
    :if ($endOctet4 > 254) do={
        :set endOctet3 ($privOctet3 + 1)
        :set endOctet4 ($endOctet4 - 254)
    }
    :local privEnd "$PrivateBase.$endOctet3.$endOctet4"

    :log info "Bloque $blockNum: $privStart-$privEnd -> $pubAddr ($clientsThisBlock clientes)"

    /ip firewall nat add \
        chain=srcnat \
        action=jump \
        jump-target="clients-$blockNum" \
        src-address="$privStart-$privEnd" \
        out-interface-list=$OutInterfaceList \
        comment="CGNAT-bloque-$blockNum"

    :delay $delay_entre_reglas

    :local currentPort $StartingPort
    :for c from=1 to=$clientsThisBlock do={

        :local clientAddr "$PrivateBase.$privOctet3.$privOctet4"
        :local portEnd ($currentPort + $PortsPerClient - 1)

        /ip firewall nat add \
            chain="clients-$blockNum" \
            action=jump \
            jump-target="client-$blockNum-$c" \
            src-address="$clientAddr" \
            comment="CGNAT-cliente-$blockNum-$c"

        :delay $delay_entre_reglas

        /ip firewall nat add \
            chain="client-$blockNum-$c" \
            action=src-nat \
            protocol=tcp \
            src-address="$clientAddr" \
            to-address="$pubAddr" \
            to-ports="$currentPort-$portEnd" \
            out-interface-list=$OutInterfaceList \
            comment="CGNAT-$clientAddr-tcp"

        :delay $delay_entre_reglas

        /ip firewall nat add \
            chain="client-$blockNum-$c" \
            action=src-nat \
            protocol=udp \
            src-address="$clientAddr" \
            to-address="$pubAddr" \
            to-ports="$currentPort-$portEnd" \
            out-interface-list=$OutInterfaceList \
            comment="CGNAT-$clientAddr-udp"

        :delay $delay_entre_clientes

        :set currentPort ($currentPort + $PortsPerClient)

        :set privOctet4 ($privOctet4 + 1)
        :if ($privOctet4 > 254) do={
            :set privOctet4 1
            :set privOctet3 ($privOctet3 + 1)
        }
    }

    :set currentPublicIP ($currentPublicIP - 1)
    :set blockNum ($blockNum + 1)

    :delay $delay_entre_bloques
}

:log info "CGNAT completado: $TotalClients clientes procesados"
