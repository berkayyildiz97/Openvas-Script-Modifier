###############################################################################
# OpenVAS Vulnerability Test
#
# IBM DB2 Multiple Vulnerabilities (Windows)
#
# Authors:
# Antu Sanadi<santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.101106");
  script_version("2019-12-19T07:02:34+0000");
  script_tag(name:"last_modification", value:"2019-12-19 07:02:34 +0000 (Thu, 19 Dec 2019)");
  script_tag(name:"creation_date", value:"2009-08-24 07:49:31 +0200 (Mon, 24 Aug 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-2859", "CVE-2009-2860");
  script_name("IBM DB2 Multiple Vulnerabilities (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Databases");
  script_dependencies("secpod_ibm_db2_detect_win_900218.nasl");
  script_mandatory_keys("Win/IBM-db2/Ver");

  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/2293");
  script_xref(name:"URL", value:"ftp://ftp.software.ibm.com/ps/products/db2/fixes/english-us/aparlist/db2_v82/APARLIST.TXT");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24024075");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause a denial of service or
  compromise a vulnerable system.");

  script_tag(name:"affected", value:"IBM DB2 version 8.1 prior to Fixpak 18");

  script_tag(name:"insight", value:"The flaws are due to:

  - An unspecified error when using DAS command may allow attackers to gain
    unauthorized access to a vulnerable database.

  - An unspecified error when processing malformed packets can be exploited
    to cause DB2JDS to crash creating a denial of service condition.");

  script_tag(name:"solution", value:"Update IBM DB2 Version 8.1 Fixpak 18.");

  script_tag(name:"summary", value:"The host is installed with IBM DB2 and is prone to multiple
  vulnerabilities.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

CPE = "cpe:/a:ibm:db2";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! version = get_app_version( cpe:CPE ) )
  exit( 0 );

if( version_in_range( version:version, test_version:"8.1",test_version2:"8.1.17" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"8.1 Fixpak 18" );
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit( 0 );
}

exit( 99 );
