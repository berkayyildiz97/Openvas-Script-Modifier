# Copyright (C) 2017 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:avast:antivirus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810902");
  script_version("2019-10-29T06:41:59+0000");
  script_cve_id("CVE-2017-5567");
  script_bugtraq_id(97017);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-10-29 06:41:59 +0000 (Tue, 29 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-04-05 10:13:58 +0530 (Wed, 05 Apr 2017)");
  script_name("Avast Free Antivirus DoubleAgent Attack Local Code Injection Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Avast Free Antivirus
  and is prone to local code injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to the product do not
  use the Protected Processes feature, and therefore an attacker can enter an
  arbitrary Application Verifier Provider DLL under Image File Execution Options
  in the registry. The self-protection mechanism is intended to block all local
  processes (regardless of privileges) from modifying Image File Execution Options
  for this product. This mechanism can be bypassed by an attacker who
  temporarily renames Image File Execution Options during the attack.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  attacker to execute arbitrary code in the context of the system running the
  affected application. This can also result in the attacker gaining complete
  control of the affected application.");

  script_tag(name:"affected", value:"Avast Free Antivirus versions prior to 17.0.");

  script_tag(name:"solution", value:"Update to Avast Free Antivirus version
  17.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://forum.avast.com/index.php?topic=199290.0");
  script_xref(name:"URL", value:"http://feeds.security-database.com/~r/Last100Alerts/~3/M6mwzAVFo-U/detail.php");
  script_xref(name:"URL", value:"https://www.engadget.com/2017/03/21/doubleagent-attack-anti-virus-hijack-your-pc");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_avast_av_detect_win.nasl");
  script_mandatory_keys("avast/antivirus_free/detected");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"17.0" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"17.0", install_path:location );
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit( 0 );
}

exit( 99 );
