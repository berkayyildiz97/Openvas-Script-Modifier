# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.900719");
  script_version("2019-11-01T13:58:25+0000");
  script_tag(name:"last_modification", value:"2019-11-01 13:58:25 +0000 (Fri, 01 Nov 2019)");
  script_tag(name:"creation_date", value:"2009-05-29 07:35:11 +0200 (Fri, 29 May 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1784");
  script_bugtraq_id(34895);
  script_name("AVG AntiVirus Engine Malware Detection Bypass Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/50426");
  script_xref(name:"URL", value:"http://blog.zoller.lu/2009/04/avg-zip-evasion-bypass.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Remote file access");
  script_dependencies("secpod_avg_detect_win.nasl");
  script_mandatory_keys("avg/antivirus/detected");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker craft malwares in a crafted
  archive file and spread it across the network to gain access to sensitive
  information or cause damage to the remote system.");
  script_tag(name:"affected", value:"AVG Anti-Virus prior to 8.5.323
  AVG File Server Edition prior to 8.5.323 on Windows");
  script_tag(name:"insight", value:"Error in the file parsing engine can be exploited to bypass the anti-virus
  scanning functionality via a specially crafted ZIP or RAR file.");
  script_tag(name:"solution", value:"Upgrade to the AVG Anti-Virus Scanning Engine build 8.5.323.");
  script_tag(name:"summary", value:"This host is installed with AVG AntiVirus Product Suite for Windows
  and is prone to Malware Detection Bypass Vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

version = infos['version'];
location = infos['location'];

if( version_is_less( version:version, test_version:"8.5.323" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"8.5.323", install_path:location );
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit( 0 );
}

exit( 99 );
