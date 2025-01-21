      ###############################################################
      ###############################################################
      ## This is a experimental overlay not ment for use right now ##
      ###############################################################
      ###############################################################

## sys-kernel/hardend-sources ##

This kernel uses anthraxx fork of the graphene source, with patch sets from both debian and gentoo.

The kernel source in this overlay needs a saved .config in this directory.

#mkdir /etc/portage/savedconfig/sys-kernel/hardened-sources

You will need to make one and copy it over.

#cp /var/git/liguros-xxx/sys-kernel/hardened-sources/files/.config /etc/portage/savedconfig/sys-kernel/hardened-sources/

#cp /usr/src/linux/.config /etc/portage/savedconfig/sys-kernel/hardened-sources/

The config make function is broken right now and dont have a fix at the moment.

## usr/src/initramfs ##

This was a initramfs make for gentoo but looks that I need to change it for this kernel, its for the config I provide but is broken.


Thank give to those that made some of what in use and/or charge for use in this
