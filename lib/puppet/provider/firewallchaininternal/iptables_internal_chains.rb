
Puppet::Type.type(:firewallchain).provide :iptables_chain do
  @doc = "Iptables chain provider for tables"

  has_feature :iptables_chain
  has_feature :policy

  commands :iptables => '/sbin/iptables'
  commands :iptables_save => '/sbin/iptables-save'

  commands :ip6tables => '/sbin/ip6tables'
  commands :ip6tables_save => '/sbin/ip6tables-save'

  commands :ebtables => '/sbin/ebtables'
  commands :ebtables_save => '/sbin/ebtables-save'

  defaultfor :kernel => :linux

  Mapping = { 'IPv4' => { 'tables' => method( :iptables ), 'save' => method( :iptables_save) },
               'IPv6' => { 'tables' => method( :ip6tables ), 'save' => method( :ip6tables_save ) },
               'EB' => { 'tables' => method( :ebtables ), 'save' => method( :ebtables_save ) }
             }
  InternalChains = 'PREROUTING|POSTROUTING|BROUTING|INPUT|FORWARD|OUTPUT'
  Tables = 'NAT|MANGLE|FILTER|RAW|RAWPOST|BROUTE|'
  Nameformat = /^(#{Tables}):([^:]+):(IP(v[46])?|ethernet)$/

  def create
    # can't create internal chains
    return if @resource[:name] =~ /^#{InternalChains}$/
    allvalidchains { |t table chain|
      debug 'Inserting chain #{chain} on table #{table}'
      t.call ['-t',table,'-N',chain] 
    }
  end

  def destroy
    # can't delete internal chains
    return if @resource[:name] =~ /^#{InternalChains}$/
    allvalidchains { |t table chain|
      debug 'Deleting chain #{chain} on table #{table}'
      t.call ['-t',table,'-X',chain] 
    }
  end

  def exists?
    properties[:ensure] != :absent
  end

  def policy=(value)
    allvalidchains { |t table chain|
      p =  ['-t',table,'-P',chain,value.to_s.upcase]
      debug "[set policy] #{t} #{p}"
      t.call p
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

    Mapping.each { |protocol, c|
      c['save'].call.split("\n").each do |line|
        # chain name is greedy so we anchor from the end.
        # [\d+:\d+] doesn't exist on ebtables
        if line =~ /^:(.+)\s(\w+)(\s\[\d+:\d+)?]$/ then
          name = (table == 'filter' ? '' : table.upcase) + ':' + $1
          policy = $2 == '-' ? :empty : $2.to_sym
          if protocol=='IPv6' && hash[name + ':']
            # duplicate so create a {table}:{chain}:IP instance
            ippolicy = hash[name + ':'] == policy ? policy : :inconsistent
            ipname = name + ':'
            hash[ipname] = ippolicy
            chains << new({:name => ipname, :policy => ippolicy })
            debug "[dup] #{ipname}, #{ippolicy}"
          end
          name += ':' + protocol
          hash[name] = policy
          chains << new({:name => name, :policy => policy })
          debug "#{name}, #{policy}"
        elsif line =~ /^\*(\S+)/
          table = $1
        end
      end
    }
    chains
  end


  private def allvalidchains
    tables = []
    @resource[:name].match(Nameformat)
    table = ($1=='') ? 'filter' : $1.downcase
    chain = $2
    protocol = $3
    if protocol == 'IP' or protocol == ''
      tables << Mapping['IPv4']['tables']
      tables << Mapping['IPv6']['tables']
    else
      tables << Mapping[protocol]['tables']
    end
    tables.each { |t| 
      yield t,table,chain,protocol
    }
  end
 
end
