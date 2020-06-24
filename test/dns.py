import dns
import dns.resolver

my_resolver = dns.resolver.Resolver()

my_resolver.nameservers = ['8.8.8.8']

result = my_resolver.query('tutorialspoint.com', 'A')
for ipval in result:
    print('IP', ipval.to_text())

result = my_resolver.query('tutorialspoint.com', 'A', tcp=True)
for ipval in result:
    print('IP', ipval.to_text())

	