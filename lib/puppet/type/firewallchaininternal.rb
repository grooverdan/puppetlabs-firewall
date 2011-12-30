
Puppet::Type.newtype(:firewallchain) do

  @doc = <<-EOS
    This type provides the capability to manage iptables chains and policies on
    internal chains within puppet.
  EOS

  InternalChains = 'PREROUTING|POSTROUTING|BROUTING|INPUT|FORWARD|OUTPUT'
  Tables = 'NAT|MANGLE|FILTER|RAW|RAWPOST|BROUTE|'
  # Technically colons (':') are allowed in table names however it requires
  # ruby-1.9 to do a regex to allow a backslash escaping of the colon.
  # ruby-1.9 regex:  Nameformat = /^(<table>#{Tables}):(<chain>([^:]*(?<!\\))+):(<protocol>IP(v[46])?|EB)?$/
  Nameformat = /^(#{Tables}):([^:]+):(IP(v[46])?|ethernet)$/

  feature :iptables_chain, "The provider provides iptables chain features."
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
        raise ArgumentError, "Inbuilt chains must be in the form {chain}:{table}:{protocol} where {table} is one of FILTER, NAT, MANGLE, RAW, RAWPOST, BROUTE or empty (alias for filter), chain can be anything without colons or one of PREROUTING, POSTROUTING, BROUTING, INPUT, FORWARD, OUTPUT for the inbuilt chains, and {protocol} being empty or IP (both meaning IPv4 and IPv6), IPv4, IPv6, ethernet (ethernet bridging) got '#{value}' table:'#{$1}' chain:'#{$2}' protocol:'#{$3}'"
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
          if protocol =~/^(IP(v6)?)?$/
            raise ArgumentError, "table nat isn't valid in IPv6 (or the default IP which is IPv4 and IPv6). You must specify ':IPv4' in the name"
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
    newvalues(:accept, :drop, :queue, :return, :empty)
    defaultto :empty
  end

  validate do
    debug("[validate]")

    value(:name).match(Nameformat)
    table = $1
    chain = $2
    protocol = $3

    # Check that we're removing and internal chain
    if chain =~ /^#{InternalChains}/
      if value(:ensure).to_s == "absent"
        self.fail "Cannot remove in-built chains"
      end
    else
    # Check that we're not setting a policy on a user chain
      if value(:policy).to_s != "empty"  &&
        self.fail 'policy can only be set on in-built chains'
      end
    end
 
    # no DROP policy on nat table
    if table == 'nat' &&
       value(:policy).to_s == 'DROP'
      self.fail 'The "nat" table is not intended for filtering, the use of DROP is therefore inhibited'
    end
  end
end
