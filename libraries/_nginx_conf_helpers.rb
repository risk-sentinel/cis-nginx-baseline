# encoding: UTF-8
#
# _nginx_conf_helpers — correct accessor for http-context NGINX directives.
#
# BUG THIS FIXES (sparc-validate#161): controls were reading http-level
# directives via `nginx_conf(path).http.params['X']`, but the object returned by
# `.http` (Inspec::Resources::NginxConfHttp) has NO `params` method — it exposes
# only `.servers`, `.locations`, `.entries`. So `conf.http.params[...]` raises
# `NoMethodError: undefined method 'params' for ...NginxConfHttp` at exec. The
# whole profile is `exec_validated: false`, so this was never caught until the
# profile was actually exec'd against an nginx target.
#
# Http-level directives instead live under `conf.params['http']` — an Array of
# block-hashes, each keyed by directive name with array-of-arg-array values
# (e.g. {'ssl_protocols' => [['TLSv1.3']]}). This helper returns that value in
# the SAME array-of-arg-arrays shape the old (broken) `conf.http.params['X']`
# was assumed to return, so existing `Array(...).flatten.first` /
# `.flatten.map(&:to_s)` / `.empty?` call sites keep working unchanged.
#
# Loaded into control bodies via `::Inspec::Rule.include` (bare
# `Inspec::Rule.include` raises uninitialized-constant under InSpec 7).

module NginxConfHelpers
  # Values of an http-level directive (array of arg-arrays). Drop-in for the
  # old `conf.http.params['<directive>']`.
  def nginx_http_values(conf, directive)
    Array(conf.params['http']).flat_map do |blk|
      blk.is_a?(Hash) ? Array(blk[directive.to_s]) : []
    end
  end

  # Values of a directive across BOTH the http context AND every server block —
  # for controls that should honour a directive set at either scope.
  def nginx_directive_values(conf, directive)
    vals = nginx_http_values(conf, directive)
    conf.http.servers.each { |s| vals.concat(Array(s.params[directive.to_s])) }
    vals
  end
end

::Inspec::Rule.include(NginxConfHelpers)
