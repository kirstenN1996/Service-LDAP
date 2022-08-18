use 5.00010;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'Service::LDAP',
    VERSION_FROM      => 'lib/Service/LDAP.pm', # finds $VERSION, requires EU::MM from perl >= 5.5
    PREREQ_PM         => {'Test'        =>  0, }, # e.g., Module::Name => 1.1
    ABSTRACT_FROM     => 'lib/Service/LDAP.pm', # retrieve abstract from module
    AUTHOR            => 'root <root@>',
    #LICENSE           => 'perl',
    #Value must be from legacy list of licenses here
    #http://search.cpan.org/perldoc?Module%3A%3ABuild%3A%3AAPI
);
