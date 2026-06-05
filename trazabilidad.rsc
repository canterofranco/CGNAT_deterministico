:local TotalClients    200
:local FirstPublicIP   8
:local PublicBase      "200.43.43"
:local PrivateBase     "100.76"
:local ClientsPerPubIP 32
:local PortsPerClient  2000
:local StartingPort    1024
:local OutIfList       "mi-wan"

:if (($StartingPort + ($ClientsPerPubIP * $PortsPerClient) - 1) > 65535) do={
    :error "ERROR: overflow de puertos. Reduci ClientsPerPubIP o PortsPerClient."
}

:local totalBlocks (($TotalClients + $ClientsPerPubIP - 1) / $ClientsPerPubIP)
:local privOctet3 0
:local privOctet4 1
:local currentPublicIP $FirstPublicIP
:local blockNum 1

:for block from=1 to=$totalBlocks do={

    :local clientsThisBlock $ClientsPerPubIP
    :if (($TotalClients - (($block - 1) * $ClientsPerPubIP)) < $ClientsPerPubIP) do={
        :set clientsThisBlock ($TotalClients - (($block - 1) * $ClientsPerPubIP))
    }

    :if ($currentPublicIP < 1) do={
        :error "ERROR: IPs publicas agotadas en bloque $blockNum"
    }

    :local privStart "$PrivateBase.$privOctet3.$privOctet4"
    :local endOctet3 $privOctet3
    :local endOctet4 ($privOctet4 + $clientsThisBlock - 1)
    :if ($endOctet4 > 254) do={
        :set endOctet3 ($privOctet3 + 1)
        :set endOctet4 ($endOctet4 - 254)
    }
    :local privEnd "$PrivateBase.$endOctet3.$endOctet4"

    :log info "Bloque $blockNum: $privStart-$privEnd -> $PublicBase.$currentPublicIP ($clientsThisBlock clientes)"

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

        /ip firewall nat add \
            chain="cgnat-block-$blockNum" \
            action=jump \
            jump-target="cgnat-c-$blockNum-$c" \
            src-address="$clientAddr" \
            comment="CGNAT-cliente-$blockNum-$c"

        :delay 20ms

        /ip firewall nat add \
            chain="cgnat-c-$blockNum-$c" \
            action=src-nat \
            protocol=tcp \
            src-address="$clientAddr" \
            to-address="$PublicBase.$currentPublicIP" \
            to-ports="$currentPort-$portEnd" \
            out-interface-list=$OutIfList \
            comment="CGNAT-$clientAddr-tcp"

        :delay 20ms

        /ip firewall nat add \
            chain="cgnat-c-$blockNum-$c" \
            action=src-nat \
            protocol=udp \
            src-address="$clientAddr" \
            to-address="$PublicBase.$currentPublicIP" \
            to-ports="$currentPort-$portEnd" \
            out-interface-list=$OutIfList \
            comment="CGNAT-$clientAddr-udp"

        :delay 20ms

        /ip firewall nat add \
            chain="cgnat-c-$blockNum-$c" \
            action=src-nat \
            src-address="$clientAddr" \
            to-address="$PublicBase.$currentPublicIP" \
            out-interface-list=$OutIfList \
            comment="CGNAT-$clientAddr-otros"

        :delay 50ms

        :set currentPort ($currentPort + $PortsPerClient)
        :set privOctet4 ($privOctet4 + 1)
        :if ($privOctet4 > 254) do={
            :set privOctet4 1
            :set privOctet3 ($privOctet3 + 1)
        }
    }

    :set currentPublicIP ($currentPublicIP - 1)
    :set blockNum ($blockNum + 1)
    :delay 2s
}
