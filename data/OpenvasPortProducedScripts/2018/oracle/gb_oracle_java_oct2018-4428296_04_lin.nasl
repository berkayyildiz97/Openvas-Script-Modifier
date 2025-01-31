###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle Java SE Security Updates-04 (oct2018-4428296) Linux
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
  script_oid("1.3.6.1.4.1.25623.1.0.814406");
  script_version("2019-09-16T06:54:58+0000");
  script_cve_id("CVE-2018-3183", "CVE-2018-3211");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-09-16 06:54:58 +0000 (Mon, 16 Sep 2019)");
  script_tag(name:"creation_date", value:"2018-10-17 13:00:25 +0530 (Wed, 17 Oct 2018)");
  script_name("Oracle Java SE Security Updates-04 (oct2018-4428296) Linux");

  script_tag(name:"summary", value:"The host is installed with Oracle Java SE
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Check if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to errors in 'Scripting'
  and 'Serviceability' components.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to gain elevated privileges and access and modify data.");

  script_tag(name:"affected", value:"Oracle Java SE version 1.8.0 to 1.8.0.182 and
  11 on Linux.");

  script_tag(name:"solution", value:"Apply the appropriate patch from the vendor. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuoct2018-4428296.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_lin.nasl");
  script_mandatory_keys("Oracle/Java/JDK_or_JRE/Linux/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE))
{
  CPE = "cpe:/a:oracle:jdk";
  if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
}

jreVer = infos['version'];
path = infos['location'];

if(jreVer =~ "^(1\.8|11)")
{
  if((version_in_range(version:jreVer, test_version:"1.8.0", test_version2:"1.8.0.182")) ||
     (version_is_equal(version:jreVer, test_version:"11")))
  {
    report = report_fixed_ver(installed_version:jreVer, fixed_version: "Apply the patch", install_path:path);
    if(!port = get_app_port(cpe: CPE)) port = 0;
    security_message(port:port, data:report);
    exit(0);
  }
}
exit(99);
