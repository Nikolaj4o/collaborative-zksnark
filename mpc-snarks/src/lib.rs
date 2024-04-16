

#[cfg(test)]
mod tests {
    use mpc_algebra::bin::F2;
    use ark_bls12_377::Fq;
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
    #[test]
    fn it_works2() {
        let el1: F2 = F2::from(true);// 1
        let el2: F2 = (0x1 as u64).into();// 1
        let el3 = el1 + el2;// 0
        let el4 = el1 + el3;// 1
        let el5 = el2 * el1;// 1
        let el6 = el2 * el3;// 0
        let el7 = el3 + el4;// 1
        let el8 = el3 * el1;// 0
        assert_eq!(el1, (1 as u64).into());
        assert_eq!(el2, (1 as u64).into());
        assert_eq!(el3, (0 as u64).into());
        assert_eq!(el4, (1 as u64).into());
        assert_eq!(el5, (1 as u64).into());
        assert_eq!(el6, (0 as u64).into());
        assert_eq!(el7, (1 as u64).into());
        assert_eq!(el8, (0 as u64).into());
        print!("{el1}, {el2}, {el3}, {el4}, {el5}, {el6}");// 1
        
    }
}
