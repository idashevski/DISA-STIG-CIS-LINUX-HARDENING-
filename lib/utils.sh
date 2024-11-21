# Function to install a package with error handling and logging
install_package() {
    local package_name=$1
    
    # Check if the package is already installed
    if dpkg -l | grep -qw "$package_name"; then
        log "INFO" "Package '$package_name' is already installed."
        return 0
    fi
    
    # Attempt to update the package list and install the package
    log "INFO" "Installing package '$package_name'..."
    if sudo apt-get update -qq && sudo apt-get install -y "$package_name"; then
        log "INFO" "Package '$package_name' installed successfully."
        return 0
    else
        log "ERROR" "Failed to install package '$package_name'."
        return 1
    fi
}
