/**
 * The candidate labels the NSEC3 act guesses with.
 *
 * This is a small, ordinary list of the names that turn up in almost every
 * zone — the kind of list anyone can assemble in an afternoon, and exactly
 * what RFC 9276 has in mind when it says an adversary "will likely be able to
 * find most of the 'guessable' names despite any level of additional hashing
 * iterations". Nothing here is exotic and nothing is derived from the target
 * zone; that is the point.
 *
 * The measurement the act reports is a RECOVERY RATE against this stated
 * candidate set, not a verdict. A recovery rate is only meaningful relative to
 * the list, and the list is right here to be read.
 */

const COMMON = `
www mail ns ns1 ns2 ns3 ns4 smtp imap pop pop3 webmail email mx mx1 mx2 relay
ftp sftp ssh vpn remote gateway gw router firewall proxy cache cdn edge origin
api api1 api2 apis rest graphql grpc ws wss socket stream
dev develop development staging stage test testing qa uat sandbox preview demo
prod production live beta alpha canary next preprod
admin administrator root manage management console panel cpanel plesk whm
portal intranet extranet internal corp corporate office hq
git gitlab github svn hg repo repos code source build ci cd jenkins bamboo
teamcity drone travis actions runner artifacts registry docker harbor nexus
jira confluence wiki docs doc documentation help support helpdesk ticket
tickets desk service servicedesk status uptime health monitor monitoring
grafana kibana prometheus alerts alertmanager metrics logs logging syslog
splunk elastic elasticsearch logstash sentry
db database sql mysql postgres postgresql mssql oracle mongo mongodb redis
memcached cassandra elastic influx timescale clickhouse warehouse dw analytics
ldap ad dc dc1 dc2 kerberos krb radius sso auth oauth oidc idp saml login
signin signup account accounts identity keycloak okta
blog news shop store cart checkout pay payment payments billing invoice
crm erp hr people workday careers jobs recruit
files file fs share shares nas storage s3 backup backups archive vault
media images img static assets content upload uploads download downloads
video audio stream live meet meeting zoom conference chat im xmpp irc slack
mobile m app apps ios android web www1 www2 www3 web1 web2 web3
srv srv1 srv2 server server1 server2 host host1 host2 node node1 node2
lb lb1 lb2 balancer haproxy nginx apache traefik envoy ingress
k8s kube kubernetes cluster swarm mesh consul vault etcd zookeeper
old new legacy tmp temp scratch spare backup1 backup2
eu us asia apac emea uk de fr es it nl se no dk fi pl ru cn jp kr in br ca au
east west north south central east1 west1 us-east us-west eu-west eu-central
a b c d e f g h i j k l m n o p q r s t u v w x y z
one two three four five six seven eight nine ten
`;

/**
 * Extra candidates in the shapes real zones actually use: a base name with a
 * digit, and the two-letter combinations that fill small zones. Generated
 * rather than listed so the list stays readable, and counted honestly in the
 * total the UI reports.
 */
const NUMBERED_BASES = ['ns', 'mx', 'www', 'web', 'db', 'srv', 'node', 'host', 'lb', 'app', 'api', 'dev'];

export function buildCandidateList(): string[] {
  const out = new Set<string>();
  for (const word of COMMON.trim().split(/\s+/)) out.add(word);
  for (const base of NUMBERED_BASES) {
    for (let n = 0; n <= 20; n += 1) out.add(`${base}${n}`);
    for (let n = 1; n <= 9; n += 1) out.add(`${base}-${n}`);
  }
  const letters = 'abcdefghijklmnopqrstuvwxyz';
  for (const a of letters) for (const b of letters) out.add(a + b);
  return [...out];
}

/** Built once; the UI reports this size beside every recovery rate. */
export const CANDIDATES: readonly string[] = buildCandidateList();
