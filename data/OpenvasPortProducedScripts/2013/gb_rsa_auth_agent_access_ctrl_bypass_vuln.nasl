###############################################################################
# OpenVAS Vulnerability Test
#
# EMC RSA Authentication Agent Access Control Bypass Vulnerability (Windows)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:emc:rsa_authentication_agent";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802059");
  script_version("2019-12-05T15:10:00+0000");
  script_cve_id("CVE-2012-2287");
  script_bugtraq_id(55662);
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-12-05 15:10:00 +0000 (Thu, 05 Dec 2019)");
  script_tag(name:"creation_date", value:"2013-08-29 12:11:58 +0530 (Thu, 29 Aug 2013)");
  script_name("EMC RSA Authentication Agent Access Control Bypass Vulnerability (Windows)");


  script_tag(name:"summary", value:"The host is installed with RSA Authentication Agent and is prone to security
bypass vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to version 7.1.1 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"insight", value:"Flaw is due to unspecified configuration, allowing users to login with
Windows credentials, which can be exploited to bypass the RSA authentication
mechanism.");
  script_tag(name:"affected", value:"RSA Authentication Agent version 7.1 on Windows XP and Windows 2003");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to bypass intended token
authentication step and establish a login session to a remote host with
Windows credentials.");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50735");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/78802");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2012-09/att-0102/ESA-2012-037.txt");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_rsa_auth_agent_detect_win.nasl");
  script_mandatory_keys("RSA/AuthenticationAgent6432/Installed");
  script_xref(name:"URL", value:"http://www.rsa.com/node.aspx?id=2575");
  exit(0);
}


include("secpod_reg.inc");
include("host_details.inc");

if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3) <= 0){
  exit(0);
}

ras_auth_ver = get_app_version(cpe:CPE);

if(ras_auth_ver && ras_auth_ver == "7.1")
{
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:"Thetargethostwasfoundtobevulnerable");
  exit(0);
}
