###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_fusion_kaslr_info_disc_vuln_macosx.nasl 11874 2018-10-12 11:28:04Z mmartin $
#
# VMware Fusion 'kASLR' Information Disclosure Vulnerability (Mac OS X)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:vmware:fusion";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809793");
  script_version("$Revision: 11874 $");
  script_cve_id("CVE-2016-5329");
  script_bugtraq_id(93888);
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:28:04 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-02-03 13:26:10 +0530 (Fri, 03 Feb 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("VMware Fusion 'kASLR' Information Disclosure Vulnerability (Mac OS X)");

  script_tag(name:"summary", value:"The host is installed with VMware Fusion
  and is prone to information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an unspecified security
  bypass error when System Integrity Protection (SIP) is enabled.");

  script_tag(name:"impact", value:"Successful exploitation will allow a
  privileged local user on a system where System Integrity Protection (SIP)
  is enabled, to obtain kernel memory addresses to bypass the kASLR protection
  mechanism.");

  script_tag(name:"affected", value:"VMware Fusion 8.x before 8.5 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to VMware Fusion version 8.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2016-0017.html");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_vmware_fusion_detect_macosx.nasl");
  script_mandatory_keys("VMware/Fusion/MacOSX/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!vmwareVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(vmwareVer =~ "^8\.")
{
  if(version_is_less(version:vmwareVer, test_version:"8.5"))
  {
    report = report_fixed_ver(installed_version:vmwareVer, fixed_version:"8.5");
    if(!port = get_app_port(cpe: CPE)) port = 0;
    security_message(port:port, data:report);
    exit(0);
  }
}
