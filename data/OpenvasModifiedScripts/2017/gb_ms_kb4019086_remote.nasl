###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft SQL Server 2016 CU Information Disclosure Vulnerability-KB4019086(Remote)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:microsoft:sql_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811568");
  script_version("2020-01-07T08:11:35+0000");
  script_cve_id("CVE-2017-8516");
  script_bugtraq_id(100041);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-01-07 08:11:35 +0000 (Tue, 07 Jan 2020)");
  script_tag(name:"creation_date", value:"2017-08-09 16:24:37 +0530 (Wed, 09 Aug 2017)");
  script_name("Microsoft SQL Server 2016 CU Information Disclosure Vulnerability-KB4019086(Remote)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4019086");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to
  Microsoft SQL Server Analysis Services when it improperly enforces
  permissions.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  an attacker to access to an affected SQL server database.");

  script_tag(name:"affected", value:"Microsoft SQL Server 2016 CU");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4019086");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("mssqlserver_detect.nasl");
  script_mandatory_keys("MS/SQLSERVER/Running");
  script_require_ports(1433);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!mssqlPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!mssqlVer = get_app_version(cpe:CPE, port:mssqlPort)){
  exit(0);
}

## security update for SQL Server 2016 CU
if(mssqlVer =~ "^13\.0")
{
  if(version_in_range(version:mssqlVer, test_version:"13.0.2000.0", test_version2:"13.0.2209.0"))
  {
    report  = 'Vulnerable range: ' + "13.0.2000.0 - 13.0.2209.0" + '\n' ;
    report = report_fixed_ver(installed_version:mssqlVer, vulnerable_range:"13.0.2000.0 - 13.0.2209.0");
    security_message(port: mssqlPort, data: report);
    exit(0);
  }
}
exit(0);
