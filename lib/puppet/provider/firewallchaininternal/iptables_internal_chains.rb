
Puppet::Type.type(:firewallchaininternal).provide :iptables_chain_internal do
  @doc = "Iptables chain provider for internal tables"

  has_feature :iptables_chain
  has_feature :policy

  commands :iptables => '/sbin/iptables'
  commands :iptables_save => '/sbin/iptables-save'

  commands :ip6tables => '/sbin/ip6tables'
  commands :ip6tables_save => '/sbin/ip6tables-save'

  commands :ebtables => '/sbin/ebtables'
  commands :ebtables_save => '/sbin/ebtables-save'

  Mapping = { 'IPv4' => { 'tables' => method( :iptables ), 'save' => method( :iptables_save) },
               'IPv6' => { 'tables' => method( :ip6tables ), 'save' => method( :ip6tables_save ) },
               'EB' => { 'tables' => method( :ebtables ), 'save' => method( :ebtables_save ) }
             }
  Chains = 'PREROUTING|POSTROUTING|BROUTING|INPUT|FORWARD|OUTPUT'
  Tables = 'NAT|MANGLE|FILTER|RAW|RAWPOST|BROUTE|'
  Nameformat = /^(#{Tables}):(#{Chains}):(IP(v[46])?|EB)$/

  def create
    debug 'Inserting chain %s' % resource[:name]
    # can't create internal tables
    return
  end

  def destroy
    debug 'Deleting chain %s' % resource[:name]
    # can't delete internal chains
    return
  end

  def exists?
    properties[:ensure] != :absent
  end

  def policy=(value)
    tables = []
    @resource[:name].match(Nameformat)
    table = ($1=='') ? 'filter' : $1.downcase
    chain = $2
    protocol = $3
    p = ['-t', table ,'-P', chain, value.to_s.upcase]
    if protocol == 'IP'
      tables << Mapping['IPv4']['tables']
      tables << Mapping['IPv6']['tables']
    else
      tables << Mapping[protocol]['tables']
    end
    tables.each { |t| 
      debug "[set policy] #{t} #{p}"
      t.call(p)
    }
  end

  def policy
    debug "[get policy] #{@resource[:name]}"
    return @property_hash[:policy].to_s.downcase
  end

  def self.prefetch(resources)
    debug("[prefetch(resources)]")
    instances.each do |prov|
      if resource = resources[prov.name]
        resource.provider = prov
      end
    end
  end

  # Look up the current status. This allows us to conventiently look up
  # existing status with properties[:foo].
  def properties
    if @property_hash.empty?
      @property_hash = query || {:ensure => :absent}
      @property_hash[:ensure] = :absent if @property_hash.empty?
    end
    @property_hash.dup
  end

  # Pull the current state of the list from the full list.
  def query
    self.class.instances.each do |instance|
      if instance.name == self.name and instance.table == self.table
        debug "query found " % instance.properties.inspect
        return instance.properties
      end
    end
    nil
  end

  def self.instances
    debug "[instances]"
    table = nil
    chains = []
    hash = {}

    # TODO merge identical IPv4/IPv6 entries
    Mapping.each { |protocol, c|
      c['save'].call.split("\n").each do |line|
        if line =~ /^:(#{Chains})\s+(\w+)/ then
          name = (table == 'filter' ? '' : table.upcase) + ':' + $1
          if protocol=='IPv6' && hash[name + ':IPv4']
             # duplicate so create a {table}:{chain}:IP instance
             policy = hash[name + ':IPv4'] == $2.to_sym ? $2.to_sym : :inconsistent
             ipname = name + ':IP'
             hash[ipname] = policy
             chains << new({:name => ipname, :policy => policy })
             debug "[dup] #{ipname}, #{policy}"
          end
          name += ':' + protocol
          hash[name] = $2.to_sym
          chains << new({:name => name, :policy => $2.to_sym })
          debug name, $2
        elsif line =~ /^\*(\S+)/
          table = $1
        end
      end
    }
    chains
  end

end
