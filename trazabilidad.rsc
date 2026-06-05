########################################
# CGNAT Determinstico
# Parmetros ajustables
########################################
:local TotalClients    500
:local FirstPublicIP   8
:local PublicBase      "200.43.43"
:local PrivateBase     "100.76"
:local ClientsPerPubIP 32
:local PortsPerClient  2000
:local StartingPort    1024
:local OutIfList       "mi-wan"


########################################
# Validacin de overflow de puertos
########################################
:if (($StartingPort + ($ClientsPerPubIP * $PortsPerClient) - 1) > 65535) do={
    :error "ERROR: overflow de puertos. Reducí ClientsPerPubIP o PortsPerClient."
}

########################################
# Clculo automtico de bloques
########################################
:local totalBlocks (($TotalClients + $ClientsPerPubIP - 1) / $ClientsPerPubIP)

:local privOctet3 0
:local privOctet4 1
:local currentPublicIP $FirstPublicIP
:local blockNum 1

:for block from=1 to=$totalBlocks do={

    # Clientes en este bloque
    :local clientsThisBlock $ClientsPerPubIP
    :local processed (($block - 1) * $ClientsPerPubIP)
    :local remaining ($TotalClients - $processed)
    :if ($remaining < $ClientsPerPubIP) do={
        :set clientsThisBlock $remaining
    }

    # Validar que quedan IPs pblicas
    :if ($currentPublicIP < 1) do={
        :error "ERROR: IPs publicas agotadas en bloque $blockNum"
    }

    :local pubAddr "$PublicBase.$currentPublicIP"

    # Calcular rango privado del bloque
    :local privStart "$PrivateBase.$privOctet3.$privOctet4"
    :local endOctet4 ($privOctet4 + $clientsThisBlock - 1)
    :local endOctet3 $privOctet3
    :if ($endOctet4 > 254) do={
        :set endOctet3 ($privOctet3 + 1)
        :set endOctet4 ($endOctet4 - 254)
    }
    :local privEnd "$PrivateBase.$endOctet3.$endOctet4"

    :log info "Bloque $blockNum: $privStart-$privEnd -> $pubAddr ($clientsThisBlock clientes)"

    # Jump principal srcnat -> cgnat-block-N
    /ip firewall nat add \
        chain=srcnat \
        action=jump \
        jump-target="cgnat-block-$blockNum" \
        src-address="$privStart-$privEnd" \
        out-interface-list=$OutIfList \
        comment="CGNAT-bloque-$blockNum"

    :delay 20ms

    :local currentPort $StartingPort
    :for c from=1 to=$clientsThisBlock do={

        :local clientAddr "$PrivateBase.$privOctet3.$privOctet4"
        :local portEnd ($currentPort + $PortsPerClient - 1)

        # Jump cgnat-block-N -> cgnat-c-N-C
        /ip firewall nat add \
            chain="cgnat-block-$blockNum" \
            action=jump \
            jump-target="cgnat-c-$blockNum-$c" \
            src-address="$clientAddr" \
            comment="CGNAT-cliente-$blockNum-$c"

        :delay 20ms

        # Regla TCP
        /ip firewall nat add \
            chain="cgnat-c-$blockNum-$c" \
            action=src-nat \
            protocol=tcp \
            src-address="$clientAddr" \
            to-address="$pubAddr" \
            to-ports="$currentPort-$portEnd" \
            out-interface-list=$OutIfList \
            comment="CGNAT-$clientAddr-tcp"

        :delay 20ms

        # Regla UDP
        /ip firewall nat add \
            chain="cgnat-c-$blockNum-$c" \
            action=src-nat \
            protocol=udp \
            src-address="$clientAddr" \
            to-address="$pubAddr" \
            to-ports="$currentPort-$portEnd" \
            out-interface-list=$OutIfList \
            comment="CGNAT-$clientAddr-udp"

        :delay 20ms

        # Regla fallback — ICMP, GRE, ESP, AH y otros
        /ip firewall nat add \
            chain="cgnat-c-$blockNum-$c" \
            action=src-nat \
            src-address="$clientAddr" \
            to-address="$pubAddr" \
            out-interface-list=$OutIfList \
            comment="CGNAT-$clientAddr-otros"

        :delay 50ms

        # Avanzar puerto
        :set currentPort ($currentPort + $PortsPerClient)

        # Avanzar IP privada
        :set privOctet4 ($privOctet4 + 1)
        :if ($privOctet4 > 254) do={
            :set privOctet4 1
            :set privOctet3 ($privOctet3 + 1)
        }
    }

    # Avanzar IP pblica descendente
    :set currentPublicIP ($currentPublicIP - 1)
    :set blockNum ($blockNum + 1)

    :delay 2s
}

:log info "CGNAT completado: $TotalClients clientes, $totalBlocks bloques."
