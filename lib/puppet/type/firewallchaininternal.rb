
Puppet::Type.newtype(:firewallchaininternal) do

  @doc = <<-EOS
    This type provides the capability to manage internal iptables chain policies within
    puppet.
  EOS

  Chains = 'PREROUTING|POSTROUTING|BROUTING|INPUT|FORWARD|OUTPUT'
  Tables = 'NAT|MANGLE|FILTER|RAW|RAWPOST|BROUTE|'
  Nameformat = /^(#{Tables}):(#{Chains}):(IP(v[46])?|EB)$/

  feature :iptables_inbuilt_chain, "The provider provides iptables chain features."
  feature :policy, "Default policy (inbuilt chains only)"

  ensurable do
    defaultvalues
    defaultto :present
  end

  newparam(:name) do
    desc <<-EOS
      The canonical name of the chain.
    EOS
    isnamevar

    validate do |value|
      if value !~ Nameformat then
        raise ArgumentError, "Inbuilt chains must be in the form {chain}:{table}:{protocol} where {table} is one of FILTER, NAT, MANGLE, RAW, RAWPOST, BROUTE or empty (alias for filter), chain must be one of PREROUTING, POSTROUTING, BROUTING, INPUT, FORWARD, OUTPUT, and {protocol} being one of IP (both IPv4 and IPv6), IPv4, IPv6, EB (ethernet bridging) got '#{value}' '#{Chains}' '#{$1}' '#{$2}' '#{$3}'"
      else 
        table = $1
        chain = $2
        protocol = $3
        case table
        when /^(FILTER|)$/
          if chain !~ /^(INPUT|OUTPUT|FORWARD)$/
            raise ArgumentError, "INPUT, OUTPUT and FORWARD are the only chains that can be used in table 'filter'"
          end
        when 'NAT'
          if chain !~ /^(PREROUTING|POSTROUTING|OUTPUT)$/
            raise ArgumentError, "PREROUTING, POSTROUTING and OUTPUT are the only chains that can be used in table 'nat'"
          end
          if protocol =~/^IP(v6)?$/
            raise ArgumentError, "table nat isn't valid in IPv6 (or IP which is IPv4 and IPv6)"
          end
        when 'RAW'
          if chain !~ /^(PREROUTING|OUTPUT)$/
            raise ArgumentError,'PREROUTING and OUTPUT are the only chains valid in the table \'raw\''
          end
        when 'BROUTE'
          if protocol != 'EB'
            raise ArgumentError,'BROUTE is only valid with protocol \'EB\''
          end
          if chain != 'BROUTING'
            raise ArgumentError,'BROUTING is the only valid chain on table \'BROUTE\''
          end
        end  
      end
    end
  end

  newproperty(:policy) do
    desc <<-EOS
      This is the action to when the end of the chain is reached.
      It can only be set on inbuilt chains ( INPUT, FORWARD, OUTPUT,
      PREROUTING, POSTROUTING) and can be one of:

      * accept - the packet is accepted
      * drop - the packet is dropped
      * queue - the packet is passed userspace
      * return - the packet is returned to calling (jump) queue
                 or the default of inbuilt chains
    EOS
    newvalues(:accept, :drop, :queue, :return)
    defaultto :return
  end

  validate do
    debug("[validate]")

    if value(:ensure).to_s == "absent"
      self.fail "Cannot remove in-built chains"
    end
    value(:name).match(Nameformat)
    table = $1
    chain = $2
    protocol = $3

    if table == 'nat' &&
       value(:policy).to_s == 'DROP'
      self.fail 'The "nat" table is not intended for filtering, the use of DROP is therefore inhibited'
    end
  end
end
