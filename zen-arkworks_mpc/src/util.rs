use std::string;

use crate::{read_vector1d, read_vector1d_f32, read_vector2d, read_vector4d};

pub struct Shallownet {
    pub x: Vec<u8>,
    pub l1_mat: Vec<Vec<u8>>,
    pub l2_mat: Vec<Vec<u8>>,
    pub x_0: Vec<u8>,
    pub l1_output_0: Vec<u8>,
    pub l2_output_0: Vec<u8>,
    pub l1_mat_0: Vec<u8>,
    pub l2_mat_0: Vec<u8>,
    pub l1_mat_multiplier: Vec<f32>,
    pub l2_mat_multiplier: Vec<f32>,
}

pub fn read_shallownet() -> Shallownet {
    let x: Vec<u8> = read_vector1d("pretrained_model/shallownet/X_q.txt".to_string(), 784); // only read one image
    let l1_mat: Vec<Vec<u8>> = read_vector2d(
        "pretrained_model/shallownet/l1_weight_q.txt".to_string(),
        128,
        784,
    );
    let l2_mat: Vec<Vec<u8>> = read_vector2d(
        "pretrained_model/shallownet/l2_weight_q.txt".to_string(),
        10,
        128,
    );
    let x_0: Vec<u8> = read_vector1d("pretrained_model/shallownet/X_z.txt".to_string(), 1);
    let l1_output_0: Vec<u8> =
        read_vector1d("pretrained_model/shallownet/l1_output_z.txt".to_string(), 1);
    let l2_output_0: Vec<u8> =
        read_vector1d("pretrained_model/shallownet/l2_output_z.txt".to_string(), 1);
    let l1_mat_0: Vec<u8> =
        read_vector1d("pretrained_model/shallownet/l1_weight_z.txt".to_string(), 1);
    let l2_mat_0: Vec<u8> =
        read_vector1d("pretrained_model/shallownet/l2_weight_z.txt".to_string(), 1);

    let l1_mat_multiplier: Vec<f32> = read_vector1d_f32(
        "pretrained_model/shallownet/l1_weight_s.txt".to_string(),
        128,
    );
    let l2_mat_multiplier: Vec<f32> = read_vector1d_f32(
        "pretrained_model/shallownet/l2_weight_s.txt".to_string(),
        10,
    );

    Shallownet {
        x,
        l1_mat,
        l2_mat,
        x_0,
        l1_output_0,
        l2_output_0,
        l1_mat_0,
        l2_mat_0,
        l1_mat_multiplier,
        l2_mat_multiplier,
    }
}

pub struct LenetFace {
    pub x: Vec<Vec<Vec<Vec<u8>>>>,
    pub conv1_w: Vec<Vec<Vec<Vec<u8>>>>,
    pub conv2_w: Vec<Vec<Vec<Vec<u8>>>>,
    pub conv3_w: Vec<Vec<Vec<Vec<u8>>>>,
    pub fc1_w: Vec<Vec<u8>>,
    pub fc2_w: Vec<Vec<u8>>,
    pub x_0: Vec<u8>,
    pub conv1_output_0: Vec<u8>,
    pub conv2_output_0: Vec<u8>,
    pub conv3_output_0: Vec<u8>,
    pub fc1_output_0: Vec<u8>,
    pub fc2_output_0: Vec<u8>,
    pub conv1_weights_0: Vec<u8>,
    pub conv2_weights_0: Vec<u8>,
    pub conv3_weights_0: Vec<u8>,
    pub fc1_weights_0: Vec<u8>,
    pub fc2_weights_0: Vec<u8>,
    pub multiplier_conv1: Vec<f32>,
    pub multiplier_conv2: Vec<f32>,
    pub multiplier_conv3: Vec<f32>,
    pub multiplier_fc1: Vec<f32>,
    pub multiplier_fc2: Vec<f32>,
    pub person_feature_vector: Vec<u8>
}

pub fn read_face() -> LenetFace {
    //println!("LeNet optimized small on ORL dataset");
    let x: Vec<Vec<Vec<Vec<u8>>>> = read_vector4d(
        "pretrained_model/LeNet_ORL_pretrained/X_q.txt".to_string(),
        1,
        1,
        56,
        46,
    ); // only read one image
    let conv1_w: Vec<Vec<Vec<Vec<u8>>>> = read_vector4d(
        "pretrained_model/LeNet_ORL_pretrained/LeNet_Small_conv1_weight_q.txt".to_string(),
        6,
        1,
        5,
        5,
    );
    let conv2_w: Vec<Vec<Vec<Vec<u8>>>> = read_vector4d(
        ("pretrained_model/LeNet_ORL_pretrained/LeNet_Small_conv2_weight_q.txt").to_string(),
        16,
        6,
        5,
        5,
    );
    let conv3_w: Vec<Vec<Vec<Vec<u8>>>> = read_vector4d(
        "pretrained_model/LeNet_ORL_pretrained/LeNet_Small_conv3_weight_q.txt".to_string(),
        120,
        16,
        4,
        4,
    );
    let fc1_w: Vec<Vec<u8>> = read_vector2d(
        "pretrained_model/LeNet_ORL_pretrained/LeNet_Small_linear1_weight_q.txt".to_string(),
        84,
        120 * 5 * 8,
    );
    let fc2_w: Vec<Vec<u8>> = read_vector2d(
        "pretrained_model/LeNet_ORL_pretrained/LeNet_Small_linear2_weight_q.txt".to_string(),
        40,
        84,
    );

    let x_0: Vec<u8> = read_vector1d(
        "pretrained_model/LeNet_ORL_pretrained/X_z.txt".to_string(),
        1,
    );
    let conv1_output_0: Vec<u8> = read_vector1d(
        "pretrained_model/LeNet_ORL_pretrained/LeNet_Small_conv1_output_z.txt".to_string(),
        1,
    );
    let conv2_output_0: Vec<u8> = read_vector1d(
        "pretrained_model/LeNet_ORL_pretrained/LeNet_Small_conv2_output_z.txt".to_string(),
        1,
    );
    let conv3_output_0: Vec<u8> = read_vector1d(
        "pretrained_model/LeNet_ORL_pretrained/LeNet_Small_conv3_output_z.txt".to_string(),
        1,
    );
    let fc1_output_0: Vec<u8> = read_vector1d(
        "pretrained_model/LeNet_ORL_pretrained/LeNet_Small_linear1_output_z.txt".to_string(),
        1,
    );
    let fc2_output_0: Vec<u8> = read_vector1d(
        "pretrained_model/LeNet_ORL_pretrained/LeNet_Small_linear2_output_z.txt".to_string(),
        1,
    );

    let conv1_weights_0: Vec<u8> = read_vector1d(
        "pretrained_model/LeNet_ORL_pretrained/LeNet_Small_conv1_weight_z.txt".to_string(),
        1,
    );
    let conv2_weights_0: Vec<u8> = read_vector1d(
        "pretrained_model/LeNet_ORL_pretrained/LeNet_Small_conv2_weight_z.txt".to_string(),
        1,
    );
    let conv3_weights_0: Vec<u8> = read_vector1d(
        "pretrained_model/LeNet_ORL_pretrained/LeNet_Small_conv3_weight_z.txt".to_string(),
        1,
    );
    let fc1_weights_0: Vec<u8> = read_vector1d(
        "pretrained_model/LeNet_ORL_pretrained/LeNet_Small_linear1_weight_z.txt".to_string(),
        1,
    );
    let fc2_weights_0: Vec<u8> = read_vector1d(
        "pretrained_model/LeNet_ORL_pretrained/LeNet_Small_linear2_weight_z.txt".to_string(),
        1,
    );

    let multiplier_conv1: Vec<f32> = read_vector1d_f32(
        "pretrained_model/LeNet_ORL_pretrained/LeNet_Small_conv1_weight_s.txt".to_string(),
        6,
    );
    let multiplier_conv2: Vec<f32> = read_vector1d_f32(
        "pretrained_model/LeNet_ORL_pretrained/LeNet_Small_conv2_weight_s.txt".to_string(),
        16,
    );
    let multiplier_conv3: Vec<f32> = read_vector1d_f32(
        "pretrained_model/LeNet_ORL_pretrained/LeNet_Small_conv3_weight_s.txt".to_string(),
        120,
    );

    let multiplier_fc1: Vec<f32> = read_vector1d_f32(
        "pretrained_model/LeNet_ORL_pretrained/LeNet_Small_linear1_weight_s.txt".to_string(),
        84,
    );
    let multiplier_fc2: Vec<f32> = read_vector1d_f32(
        "pretrained_model/LeNet_ORL_pretrained/LeNet_Small_linear2_weight_s.txt".to_string(),
        40,
    );

    let person_feature_vector: Vec<u8> = read_vector1d(
        "pretrained_model/LeNet_ORL_pretrained/person_feature_vector.txt".to_string(),
        40,
    );

    LenetFace {
      x,
      conv1_w,
      conv2_w,
      conv3_w,
      fc1_w,
      fc2_w,
      x_0,
      conv1_output_0,
      conv2_output_0,
      conv3_output_0,
      fc1_output_0,
      fc2_output_0,
      conv1_weights_0,
      conv2_weights_0,
      conv3_weights_0,
      fc1_weights_0,
      fc2_weights_0,
      multiplier_conv1,
      multiplier_conv2,
      multiplier_conv3,
      multiplier_fc1,
      multiplier_fc2,
      person_feature_vector
    }
}

pub struct LenetCifar {
    pub x: Vec<Vec<Vec<Vec<u8>>>>,
    pub conv1_w: Vec<Vec<Vec<Vec<u8>>>>,
    pub conv2_w: Vec<Vec<Vec<Vec<u8>>>>,
    pub conv3_w: Vec<Vec<Vec<Vec<u8>>>>,
    pub fc1_w: Vec<Vec<u8>>,
    pub fc2_w: Vec<Vec<u8>>,
    pub x_0: Vec<u8>,
    pub conv1_output_0: Vec<u8>,
    pub conv2_output_0: Vec<u8>,
    pub conv3_output_0: Vec<u8>,
    pub fc1_output_0: Vec<u8>,
    pub fc2_output_0: Vec<u8>,
    pub conv1_weights_0: Vec<u8>,
    pub conv2_weights_0: Vec<u8>,
    pub conv3_weights_0: Vec<u8>,
    pub fc1_weights_0: Vec<u8>,
    pub fc2_weights_0: Vec<u8>,
    pub multiplier_conv1: Vec<f32>,
    pub multiplier_conv2: Vec<f32>,
    pub multiplier_conv3: Vec<f32>,
    pub multiplier_fc1: Vec<f32>,
    pub multiplier_fc2: Vec<f32>,
}

pub fn read_cifar() -> LenetCifar {
    //println!("LeNet optimized small on ORL dataset");
    let x: Vec<Vec<Vec<Vec<u8>>>> = read_vector4d(
        "pretrained_model/LeNet_CIFAR_pretrained/X_q.txt".to_string(),
        1,
        3,
        32,
        32,
    ); // only read one image
    let conv1_w: Vec<Vec<Vec<Vec<u8>>>> = read_vector4d(
        "pretrained_model/LeNet_CIFAR_pretrained/LeNet_Small_conv1_weight_q.txt".to_string(),
        6,
        3,
        5,
        5,
    );
    let conv2_w: Vec<Vec<Vec<Vec<u8>>>> = read_vector4d(
        "pretrained_model/LeNet_CIFAR_pretrained/LeNet_Small_conv2_weight_q.txt".to_string(),
        16,
        6,
        5,
        5,
    );
    let conv3_w: Vec<Vec<Vec<Vec<u8>>>> = read_vector4d(
        "pretrained_model/LeNet_CIFAR_pretrained/LeNet_Small_conv3_weight_q.txt".to_string(),
        120,
        16,
        4,
        4,
    );
    let fc1_w: Vec<Vec<u8>> = read_vector2d(
        "pretrained_model/LeNet_CIFAR_pretrained/LeNet_Small_linear1_weight_q.txt".to_string(),
        84,
        480,
    );
    let fc2_w: Vec<Vec<u8>> = read_vector2d(
        "pretrained_model/LeNet_CIFAR_pretrained/LeNet_Small_linear2_weight_q.txt".to_string(),
        10,
        84,
    );

    let x_0: Vec<u8> = read_vector1d(
        "pretrained_model/LeNet_CIFAR_pretrained/X_z.txt".to_string(),
        1,
    );
    let conv1_output_0: Vec<u8> = read_vector1d(
        "pretrained_model/LeNet_CIFAR_pretrained/LeNet_Small_conv1_output_z.txt".to_string(),
        1,
    );
    let conv2_output_0: Vec<u8> = read_vector1d(
        "pretrained_model/LeNet_CIFAR_pretrained/LeNet_Small_conv2_output_z.txt".to_string(),
        1,
    );
    let conv3_output_0: Vec<u8> = read_vector1d(
        "pretrained_model/LeNet_CIFAR_pretrained/LeNet_Small_conv3_output_z.txt".to_string(),
        1,
    );
    let fc1_output_0: Vec<u8> = read_vector1d(
        "pretrained_model/LeNet_CIFAR_pretrained/LeNet_Small_linear1_output_z.txt".to_string(),
        1,
    );
    let fc2_output_0: Vec<u8> = read_vector1d(
        "pretrained_model/LeNet_CIFAR_pretrained/LeNet_Small_linear2_output_z.txt".to_string(),
        1,
    );

    let conv1_weights_0: Vec<u8> = read_vector1d(
        "pretrained_model/LeNet_CIFAR_pretrained/LeNet_Small_conv1_weight_z.txt".to_string(),
        1,
    );
    let conv2_weights_0: Vec<u8> = read_vector1d(
        "pretrained_model/LeNet_CIFAR_pretrained/LeNet_Small_conv2_weight_z.txt".to_string(),
        1,
    );
    let conv3_weights_0: Vec<u8> = read_vector1d(
        "pretrained_model/LeNet_CIFAR_pretrained/LeNet_Small_conv3_weight_z.txt".to_string(),
        1,
    );
    let fc1_weights_0: Vec<u8> = read_vector1d(
        "pretrained_model/LeNet_CIFAR_pretrained/LeNet_Small_linear1_weight_z.txt".to_string(),
        1,
    );
    let fc2_weights_0: Vec<u8> = read_vector1d(
        "pretrained_model/LeNet_CIFAR_pretrained/LeNet_Small_linear2_weight_z.txt".to_string(),
        1,
    );

    let multiplier_conv1: Vec<f32> = read_vector1d_f32(
        "pretrained_model/LeNet_CIFAR_pretrained/LeNet_Small_conv1_weight_s.txt".to_string(),
        6,
    );
    let multiplier_conv2: Vec<f32> = read_vector1d_f32(
        "pretrained_model/LeNet_CIFAR_pretrained/LeNet_Small_conv2_weight_s.txt".to_string(),
        16,
    );
    let multiplier_conv3: Vec<f32> = read_vector1d_f32(
        "pretrained_model/LeNet_CIFAR_pretrained/LeNet_Small_conv3_weight_s.txt".to_string(),
        120,
    );

    let multiplier_fc1: Vec<f32> = read_vector1d_f32(
        "pretrained_model/LeNet_CIFAR_pretrained/LeNet_Small_linear1_weight_s.txt".to_string(),
        84,
    );
    let multiplier_fc2: Vec<f32> = read_vector1d_f32(
        "pretrained_model/LeNet_CIFAR_pretrained/LeNet_Small_linear2_weight_s.txt".to_string(),
        10,
    );

    LenetCifar {
      x,
      conv1_w,
      conv2_w,
      conv3_w,
      fc1_w,
      fc2_w,
      x_0,
      conv1_output_0,
      conv2_output_0,
      conv3_output_0,
      fc1_output_0,
      fc2_output_0,
      conv1_weights_0,
      conv2_weights_0,
      conv3_weights_0,
      fc1_weights_0,
      fc2_weights_0,
      multiplier_conv1,
      multiplier_conv2,
      multiplier_conv3,
      multiplier_fc1,
      multiplier_fc2,
    }
}