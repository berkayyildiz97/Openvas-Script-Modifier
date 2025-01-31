###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Flash Player End Of Life Detection (Mac OS X)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814040");
  script_version("2019-12-05T15:10:00+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-12-05 15:10:00 +0000 (Thu, 05 Dec 2019)");
  script_tag(name:"creation_date", value:"2018-09-21 12:06:57 +0530 (Fri, 21 Sep 2018)");
  script_name("Adobe Flash Player End Of Life Detection (Mac OS X)");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Flash/Player/MacOSX/Version");

  script_xref(name:"URL", value:"https://helpx.adobe.com/in/flash-player/kb/flash-player-9-support-discontinued.html");

  script_tag(name:"summary", value:"The Adobe Flash Player version on the remote
  host has reached the end of life and should not be used anymore.");

  script_tag(name:"impact", value:"An end of life version of Adobe Flash Player is
  not receiving any security updates from the vendor. Unfixed security vulnerabilities
  might be leveraged by an attacker to compromise the security of this host.");

  script_tag(name:"solution", value:"Update the Adobe Flash Player version on the
  remote host to a still supported version.");

  script_tag(name:"vuldetect", value:"Checks if an unsupported version is present
  on the target host.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("misc_func.inc");
include("products_eol.inc");
include("host_details.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

if( ret = product_reached_eol( cpe:CPE, version:version ) ) {

  report = build_eol_message( name:"Adobe Flash Player",
                              cpe:CPE,
                              version:version,
                              eol_version:ret["eol_version"],
                              eol_date:ret["eol_date"],
                              eol_type:"prod" );
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit( 0 );
}

exit( 99 );
