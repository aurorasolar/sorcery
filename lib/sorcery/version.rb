module Sorcery
  # This is not the same version as main sorcery repo.
  # Compared to 0.14.0 it only fixes security vulnerability.
  # The version is bumped for dependency checks to recognize this security patch.
  # TODO: we should use main sorcery and sorcery-jwt gems, not private forks
  VERSION = '0.15.0'.freeze
end
