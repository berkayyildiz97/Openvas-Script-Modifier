###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle Virtualbox Multiple Unspecified Vulnerabilities July17 (Linux)
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

CPE = "cpe:/a:oracle:vm_virtualbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811530");
  script_version("2019-09-20T11:01:01+0000");
  script_cve_id("CVE-2017-10204", "CVE-2017-10129", "CVE-2017-10210", "CVE-2017-10233",
                "CVE-2017-10236", "CVE-2017-10237", "CVE-2017-10238", "CVE-2017-10239",
                "CVE-2017-10240", "CVE-2017-10241", "CVE-2017-10242", "CVE-2017-10235",
                "CVE-2017-10209", "CVE-2017-10187");
  script_bugtraq_id(99631, 99638, 99640, 99642, 99645, 99667, 99668, 99683, 99687, 99689,
                    99705, 99709, 99711);
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-09-20 11:01:01 +0000 (Fri, 20 Sep 2019)");
  script_tag(name:"creation_date", value:"2017-07-19 11:45:06 +0530 (Wed, 19 Jul 2017)");
  script_name("Oracle Virtualbox Multiple Unspecified Vulnerabilities July17 (Linux)");

  script_tag(name:"summary", value:"This host is installed with Oracle VM
  VirtualBox and is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple
  unspecified errors related to core component of the application.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to have an impact on availability, confidentiality and integrity.");

  script_tag(name:"affected", value:"VirtualBox versions prior to 5.1.24
  on Linux.");

  script_tag(name:"solution", value:"Upgrade to Oracle VirtualBox 5.1.24 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpujul2017-3236622.html");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_sun_virtualbox_detect_lin.nasl");
  script_mandatory_keys("Sun/VirtualBox/Lin/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!virtualVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:virtualVer, test_version:"5.1.24"))
{
  report = report_fixed_ver( installed_version:virtualVer, fixed_version:"5.1.24");
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit(0);
}
