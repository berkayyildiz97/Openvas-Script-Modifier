###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openttd_mult_use_after_free_dos_vuln.nasl 12602 2018-11-30 14:36:58Z cfischer $
#
# OpenTTD Multiple use-after-free Denial of Service Vulnerabilities
#
# Authors:
# Veerendra GG <veerendrgg@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.800184");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2010-11-30 12:42:12 +0100 (Tue, 30 Nov 2010)");
  script_cve_id("CVE-2010-4168");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("OpenTTD Multiple use-after-free Denial of Service vulnerability");
  script_xref(name:"URL", value:"http://security.openttd.org/en/CVE-2010-4168");
  script_xref(name:"URL", value:"http://security.openttd.org/en/patch/28.patch");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Denial of Service");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to deny service to
  legitimate users or arbitrary code execution.");
  script_tag(name:"affected", value:"OpenTTD version before 1.0.5");
  script_tag(name:"insight", value:"The flaw is due to a use-after-free error, when a client disconnects
  without sending the 'quit' or 'client error' message. This could cause a
  vulnerable server to read from or write to freed memory leading to a denial
  of service or it can also lead to arbitrary code execution.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to the latest version of OpenTTD 1.0.5 or later.");
  script_tag(name:"summary", value:"This host is installed with OpenTTD and is prone to multiple
  denial of service vulnerability.");
  script_xref(name:"URL", value:"http://www.openttd.org");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");


if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\OpenTTD";
openttd_ver = registry_get_sz(key:key, item:"DisplayVersion");

if(openttd_ver)
{
  if(version_is_less(version:openttd_ver, test_version:"1.0.5")){
    report = report_fixed_ver(installed_version:openttd_ver, fixed_version:"1.0.5");
    security_message(port: 0, data: report);
  }
}
