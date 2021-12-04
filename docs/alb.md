# alb.py
## A library of routines to handle ALB (Amazon Load Balancer)

### alb_connect_sg

    Connect gravitar security group to alb.

    Args:
        grv_name: gravitar name
        cluster_name: the name of eks cluster
        public: is this a public or internal alb

    Returns: 
        success as a bool

    Example:
        is_connected = alb_connect_sg("grv", "cluster", pub_or_internal)


### alb_create

    Create an Application Load Balancer.

    Args:
        grv_name: gravitar name
        public: is this a public or internal alb

    Returns: 
        dict of alb status response or exception dict

    Example:
        return_dict = alb_create("grv", pub_or_internal)


### alb_info

    Get alb information.

    Args: 
        grv_name: gravitar name

    Returns: 
        a dictionary containing information of load balancers and security groups

    Example:
        return_dict = alb_info("grv")


### delete_alb

    Delete an ALB.

    Args:
        grv_name: gravitar name to delete ALBs from
        public: is this a public or internal alb

    Returns: 
        True if alb is deleted or not available, or False

    Example:
        a


### find_alb_arn

    Find the ALB Arn.

    Args: 
        alb_name: name of alb

    Returns: 
        ARN of the given alb, or empty string

    Example:
        a


### find_sg_attached

    Return the security group attached to a alb.

    Args: 
        alb_name: the name of the alb

    Returns: 
        the id of security group, or empty string

    Example:
        a


### get_alb_dict

    Return alb name dictionary for a gravitar and public flag.

    Args:
        gravitar: the name of the gravitor
        public: the bool flag indicating whether it is public or private

    Returns: 
        A dictionary in the format of {name, sg_name, schema, subnets}

    Example:
        a


### get_alb_status

    Get the alb status.

    Args: 
        alb_name: alb name

    Returns: 
        status dict of the response or exception dict


    Example:
        a



