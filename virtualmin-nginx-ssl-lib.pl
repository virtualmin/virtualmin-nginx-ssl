#  Common functions for NginX SSL mode plugin

use strict;
use warnings;
use Socket;

BEGIN { push(@INC, ".."); };
eval "use WebminCore;";
&init_config();
our (%config, %text, %in, $module_root_directory);

1;

