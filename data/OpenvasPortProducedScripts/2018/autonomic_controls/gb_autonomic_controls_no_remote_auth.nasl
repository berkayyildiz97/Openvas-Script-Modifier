###############################################################################
# OpenVAS Vulnerability Test
#
# Autonomic Controls Devices No Authentication
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113245");
  script_version("2019-09-06T14:17:49+0000");
  script_tag(name:"last_modification", value:"2019-09-06 14:17:49 +0000 (Fri, 06 Sep 2019)");
  script_tag(name:"creation_date", value:"2018-08-07 11:30:00 +0200 (Tue, 07 Aug 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Autonomic Controls Devices No Authentication");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_dependencies("gb_autonomic_controls_consolidation.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("autonomic_controls/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"Per default, Autonomic Controls devices
  don't have authentication enabled for remote configuration.");

  script_tag(name:"vuldetect", value:"Checks if credentials are required
  to access the device.");

  script_tag(name:"impact", value:"Successful exploitation would give an attacker
  full control over the target device. Furthermore, the device stores account credentials
  in plain base64-encoding, allowing attackers access to linked Spotify, Amazon and other accounts.");

  script_tag(name:"affected", value:"All Autonomic Controls devices.");

  script_tag(name:"solution", value:"Set a password for remote configuration by accessing the telnet interface
  and executing following commands, whereas placeholders are placed in square brackets:

  set remote user [username]

  set remote password [password]");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

CPE = "cpe:/h:autonomic_controls:device";

include("host_details.inc");
include("telnet_func.inc");
include("misc_func.inc");
include("dump.inc");

if( ! port = get_kb_item( "autonomic_controls/telnet/port" ) ) exit( 0 );

banner = telnet_get_banner( port: port );

if( banner =~ 'You are logged in' ) {
  report = "Accessing remote configuration didn't require authentication.";
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit( 0 );
}

exit( 99 );
