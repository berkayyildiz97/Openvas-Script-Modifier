###############################################################################
# OpenVAS Vulnerability Test
#
# VMware Workstation SVGA Device Code Execution Vulnerability (Windows)
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

CPE = "cpe:/a:vmware:workstation";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811835");
  script_version("2019-07-05T09:29:25+0000");
  script_cve_id("CVE-2017-4924");
  script_bugtraq_id(100843);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-07-05 09:29:25 +0000 (Fri, 05 Jul 2019)");
  script_tag(name:"creation_date", value:"2017-09-20 17:35:28 +0530 (Wed, 20 Sep 2017)");
  script_tag(name:"qod_type", value:"registry");
  script_name("VMware Workstation SVGA Device Code Execution Vulnerability (Windows)");

  script_tag(name:"summary", value:"The host is installed with VMware Workstation
  and is prone to code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an out-of-bounds write
  error in SVGA device.");

  script_tag(name:"impact", value:"Successful exploitation will allow a
  guest to execute code on the host.");

  script_tag(name:"affected", value:"VMware Workstation 12.x before
  12.5.7 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Workstation version
  12.5.7 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.vmware.com/security/advisories/VMSA-2017-0015.html");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_vmware_prdts_detect_win.nasl");
  script_mandatory_keys("VMware/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vmwareVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(vmwareVer =~ "^(12\.)")
{
  if(version_is_less(version:vmwareVer, test_version:"12.5.7"))
  {
    report = report_fixed_ver(installed_version:vmwareVer, fixed_version:"12.5.7");
    if(!port = get_app_port(cpe: CPE)) port = 0;
    security_message(port:port, data:report);
    exit(0);
  }
}
