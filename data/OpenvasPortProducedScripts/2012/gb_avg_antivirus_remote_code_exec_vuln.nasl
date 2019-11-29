# Copyright (C) 2012 Greenbone Networks GmbH
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

CPE = "cpe:/a:avg:anti-virus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802976");
  script_version("2019-11-01T13:58:25+0000");
  script_cve_id("CVE-2010-3498");
  script_bugtraq_id(44189);
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-11-01 13:58:25 +0000 (Fri, 01 Nov 2019)");
  script_tag(name:"creation_date", value:"2012-10-01 18:51:18 +0530 (Mon, 01 Oct 2012)");
  script_name("AVG Anti-Virus 'hcp://' Protocol Handler Remote Code Execution Vulnerability");

  script_xref(name:"URL", value:"http://www.n00bz.net/antivirus-cve");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/514356");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2010/Jun/205");

  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_avg_detect_win.nasl");
  script_mandatory_keys("avg/antivirus/detected");
  script_tag(name:"impact", value:"Successful exploitation could allow the attackers to bypass virus
scanning and allows an attacker to drop and execute known malicious files.");
  script_tag(name:"affected", value:"AVG Anti-Virus versions 8.0, 8.0.156 and 8.0.323");
  script_tag(name:"insight", value:"The flaw is due to an error in application when interacting
with the hcp:// URLs by the Microsoft Help and Support Center.");
  script_tag(name:"summary", value:"The host is installed with AVG Anti-Virus and is prone to remote
code execution vulnerability.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

version = infos['version'];
location = infos['location'];

if( version_is_less_equal( version:version, test_version:"8.0.323" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"None", install_path:location );
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit( 0 );
}

exit( 99 );
