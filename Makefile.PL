
use inc::Module::Install;

name            ("Dowse-BadSSH");
abstract        ("dowse for bad SSH keys on a system");
author          ("Sam Vilain <samv\@cpan.org>");
version         (0.04);
license         ("perl");

requires        ("perl" => 5.004004);  # send me bug reports if this is wrong

build_requires  ("File::Temp");
build_requires  ("File::Spec");
build_requires  ("File::Path");

auto_include;

&WriteAll();

