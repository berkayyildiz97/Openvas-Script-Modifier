###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mysql_mult_unspecified_vuln02_april16_win.nasl 2016-04-25 16:10:46 +0530 April$
#
# Oracle MySQL Multiple Unspecified Vulnerabilities-02 April16 (Windows)
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807924");
  script_version("$Revision: 12983 $");
  script_cve_id("CVE-2016-0666", "CVE-2016-0647", "CVE-2016-0648", "CVE-2016-0642",
                "CVE-2016-0643", "CVE-2016-2047");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:M/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-01-08 16:30:19 +0100 (Tue, 08 Jan 2019) $");
  script_tag(name:"creation_date", value:"2016-04-25 16:10:46 +0530 (Mon, 25 Apr 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Oracle MySQL Multiple Unspecified Vulnerabilities-02 April16 (Windows)");

  script_tag(name:"summary", value:"This host is running Oracle MySQL and is
  prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Unspecified errors exists in the MySQL Server
  component via unknown vectors related to Server.");

  script_tag(name:"impact", value:"Successful exploitation will allows remote
  users to affect confidentiality, integrity, and  availability via unknown
  vectors.");

  script_tag(name:"affected", value:"Oracle MySQL Server 5.5.48 and earlier,
  5.6.29 and earlier, and 5.7.11 and earlier on windows");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuapr2016v3-2985753.html");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_require_ports("Services/mysql", 3306);
  script_mandatory_keys("MySQL/installed", "Host/runs_windows");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

cpe_list = make_list( "cpe:/a:mysql:mysql", "cpe:/a:oracle:mysql" );

if(!infos = get_all_app_ports_from_list(cpe_list:cpe_list)) exit( 0 );
CPE = infos['cpe'];
sqlPort = infos['port'];

if(!infos = get_app_version_and_location(cpe:CPE, port:sqlPort, exit_no_version:TRUE)) exit(0);
mysqlVer = infos['version'];
mysqlPath = infos['location'];

if(mysqlVer =~ "^5\.[5-7]\.")
{
  if(version_in_range(version:mysqlVer, test_version:"5.5.0", test_version2:"5.5.48") ||
     version_in_range(version:mysqlVer, test_version:"5.6.0", test_version2:"5.6.29") ||
     version_in_range(version:mysqlVer, test_version:"5.7.0", test_version2:"5.7.11"))
  {
    report = report_fixed_ver(installed_version:mysqlVer, fixed_version:"Apply the patch", install_path:mysqlPath);
    if(!port = get_app_port(cpe: CPE)) port = 0;
    security_message(port:port, data:report);
    exit(0);
  }
}
