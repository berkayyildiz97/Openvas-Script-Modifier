###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle Java SE Security Updates-04 (jul2018-4258247) Windows
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

CPE = "cpe:/a:oracle:jre";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813686");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-2964");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-07-18 11:26:47 +0530 (Wed, 18 Jul 2018)");
  script_name("Oracle Java SE Security Updates-04 (jul2018-4258247) Windows");

  script_tag(name:"summary", value:"The host is installed with Oracle Java SE
  and is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Check if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an unspecified error
  in the Java SE Security component.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to access sensitive data.");

  script_tag(name:"affected", value:"Oracle Java SE version 10.0 through 10.0.1 and
  1.8.0.172 and earlier on Windows");

  script_tag(name:"solution", value:"Apply the appropriate patch from the vendor. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuapr2018-3678067.html");
  script_xref(name:"URL", value:"https://securitytracker.com/id/1041302");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/java/javase/downloads/index.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JRE/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
jreVer = infos['version'];
path = infos['location'];

if(jreVer =~ "^((1\.8)|10)")
{
  if((version_in_range(version:jreVer, test_version:"10.0", test_version2:"10.0.1")) ||
     (version_in_range(version:jreVer, test_version:"1.8.0", test_version2:"1.8.0.172")))
  {
    report = report_fixed_ver(installed_version:jreVer, fixed_version: "Apply the patch", install_path:path);
    if(!port = get_app_port(cpe: CPE)) port = 0;
    security_message(port:port, data:report);
    exit(0);
  }
}
exit(0);
