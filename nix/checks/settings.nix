{
  schema_version = 1;
  protocol.profile = "huawei-linux-base-v1";
  server = {
    host = "192.0.2.10";
    port = 9443;
  };
  auth = {
    username = "module-check";
    mac = "02:00:00:00:00:01";
  };
  tls.spki_sha256 = [ "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" ];
  network.allowed_routes = [ "10.20.0.0/16" ];
  socks = {
    enabled = true;
    listeners = [ "127.0.0.1:1080" ];
    allow_sources = [ "127.0.0.1/32" ];
    allow_loopback_no_auth = true;
  };
  gateway = {
    mode = "netbird";
    ingress_interface = "eth1";
    source_cidrs = [ "192.0.2.0/24" ];
    export_routes = [ "10.20.0.0/16" ];
    clamp_tcp_mss = true;
  };
}
