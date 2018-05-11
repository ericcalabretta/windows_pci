# encoding: utf-8
# copyright: 2018, The Authors
title 'windows_pci_example'

control 'PCI_DSS_v3-2 8.1.6' do
  impact 1.0
  title 'Limit repeated access attempts by locking out the user ID after not more than six attempts.'
  desc 'Without account-lockout mechanisms in place, an attacker can continually attempt to guess a password through manual or automated tools (for example, password cracking), until they achieve success and gain access to a user’s account.'
  describe security_policy do
    its('LockoutBadCount') { should be <= 6 }
  end
end

control 'PCI_DSS_v3-2 8.1.7' do                        # A unique ID for this control
  impact 1.0                                # The criticality, if this control fails.
  title 'Set the lockout duration to a minimum of 30 minutes or until an administrator enables the user ID.'             # A human-readable title
  desc 'If an account is locked out due to someone continually trying to guess a password, controls to delay reactivation of these locked accounts stops the malicious individual from continually guessing the password (they will have to stop for a minimum of 30 minutes until the account is reactivated). Additionally, if reactivation must be requested, the admin or help desk can validate that it is the actual account owner requesting reactivation.'
  describe security_policy do
     its("LockoutDuration") { should be >= 900 }
  end
end

control 'PCI_DSS_v3-2 8.2.1' do
  impact 1.0
  title 'Using strong cryptography, render all authentication credentials (such as passwords/phrases) unreadable during transmission and storage on all system components.'
  desc 'Many network devices and applications transmit unencrypted, readable passwords across the network and/or store passwords without encryption.'
  describe security_policy do
    its('ClearTextPassword') { should eq 0 }
  end
end

control 'PCI_DSS_v3-2 8.2.3' do
  impact 1.0
  title 'Passwords/passphrases must meet the following:Require a minimum length of at least seven characters. Contain both numeric and alphabetic characters.'
  desc 'Strong passwords/passphrases are the first line of defense into a network since a malicious individual will often first try to find accounts with weak or non-existent passwords. If passwords are short or simple to guess, it is relatively easy for a malicious individual to find these weak accounts and compromise a network under the guise of a valid user ID.'
  describe security_policy do
    # TODO: check that the number is greater than 8
    its('MinimumPasswordLength') { should be >= 0 }
  end
end

control 'PCI_DSS_v3-2 8.2.5' do
  impact 1.0
  title 'Do not allow an individual to submit a new password/passphrase that is the same as any of the last four passwords/passphrases he or she has used.'
  desc 'If password history isn’t maintained, the effectiveness of changing passwords is reduced, as previous passwords can be reused over and over.'
  describe security_policy do
    its('PasswordHistorySize') { should be >= 4 }
  end
end
