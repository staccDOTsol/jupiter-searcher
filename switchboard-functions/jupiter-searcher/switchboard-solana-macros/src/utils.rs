use syn::{GenericArgument, PathArguments, Type, TypePath};

/// Helper function to extract the inner type from an `Arc` type.
pub fn extract_inner_type_from_arc(ty: &Type) -> Option<&Type> {
    if let Type::Path(type_path) = ty {
        // Check for either `Arc` or `std::sync::Arc`
        let segments = &type_path.path.segments;
        let is_arc = segments.last().map_or(false, |seg| seg.ident == "Arc")
            && (segments.len() == 1 || // it's just `Arc`
                (segments.len() == 3 && // it's `std::sync::Arc`
                    segments[0].ident == "std" &&
                    segments[1].ident == "sync"));

        if is_arc {
            if let PathArguments::AngleBracketed(angle_bracketed) =
                &segments.last().unwrap().arguments
            {
                if let Some(GenericArgument::Type(inner_ty)) = angle_bracketed.args.first() {
                    return Some(inner_ty);
                }
            }
        }
    }
    None
}

/// Helper function to extract the generic arguments from a `Result` type.
pub fn extract_result_args(ty: &Type) -> Option<(&Type, &Type)> {
    if let Type::Path(TypePath { path, .. }) = ty {
        let result_segment = path.segments.iter().find(|seg| seg.ident == "Result");
        if let Some(result_segment) = result_segment {
            if let PathArguments::AngleBracketed(angle_bracketed_params) = &result_segment.arguments
            {
                if angle_bracketed_params.args.len() == 2 {
                    if let (GenericArgument::Type(first_arg), GenericArgument::Type(second_arg)) = (
                        &angle_bracketed_params.args[0],
                        &angle_bracketed_params.args[1],
                    ) {
                        return Some((first_arg, second_arg));
                    }
                }
            }
        }
    }
    None
}

pub fn extract_inner_type_from_vec(ty: &Type) -> Option<&Type> {
    if let Type::Path(type_path) = ty {
        if let Some(segment) = type_path.path.segments.iter().last() {
            if segment.ident == "Vec" {
                if let PathArguments::AngleBracketed(angle_bracketed) = &segment.arguments {
                    if let Some(GenericArgument::Type(inner_ty)) = angle_bracketed.args.first() {
                        return Some(inner_ty);
                    }
                }
            }
        }
    }
    None
}
